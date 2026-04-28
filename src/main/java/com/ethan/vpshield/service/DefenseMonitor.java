package com.ethan.vpshield.service;

import com.ethan.vpshield.config.ShieldProperties;
import com.ethan.vpshield.model.Alert;
import com.ethan.vpshield.model.PacketInfo;
import com.ethan.vpshield.model.TrafficStats;
import com.ethan.vpshield.service.defense.DefenseStrategyManager;
import com.ethan.vpshield.service.defense.IpBlocker;
import com.ethan.vpshield.service.defense.RateLimitStrategy;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;

@Slf4j
@Service
@RequiredArgsConstructor
public class DefenseMonitor {

    private final ShieldProperties properties;
    private final DefenseStrategyManager strategyManager;
    private final RateLimitStrategy rateLimitStrategy;
    private final IpBlocker ipBlocker;
    private final SnifferService snifferService;

    private final AtomicLong currentWindowPackets = new AtomicLong(0);
    private final AtomicLong currentWindowIcmp = new AtomicLong(0);
    private final AtomicLong currentWindowIcmpReply = new AtomicLong(0);
    private final AtomicLong currentWindowTcpSyn = new AtomicLong(0);
    private final AtomicLong currentWindowTcp = new AtomicLong(0);
    private final AtomicLong currentWindowUdp = new AtomicLong(0);
    private final AtomicLong currentWindowBytes = new AtomicLong(0);

    private final Set<String> currentSourceIps = ConcurrentHashMap.newKeySet();
    private final Set<String> currentDestinationIps = ConcurrentHashMap.newKeySet();
    private final BlockingQueue<TrafficStats> statsHistory = new LinkedBlockingQueue<>(60);

    private final Set<String> localIps = loadLocalIps();

    private Consumer<Alert> alertHandler;
    private Consumer<TrafficStats> statsHandler;
    private ScheduledFuture<?> statsTask;
    private ScheduledFuture<?> emergencyRecoveryTask;
    private ScheduledExecutorService scheduler;
    private volatile LocalDateTime lastAlertTime;

    @Getter
    private final Set<String> detectedAttackSources = ConcurrentHashMap.newKeySet();

    @Getter
    private volatile TrafficStats currentStats = TrafficStats.empty();

    @Getter
    private volatile boolean emergencyModeActive = false;

    @Getter
    private volatile String emergencyReason = null;

    public void startMonitoring(Consumer<TrafficStats> statsHandler, Consumer<Alert> alertHandler) {
        this.statsHandler = statsHandler;
        this.alertHandler = alertHandler;

        if (statsTask != null && !statsTask.isCancelled()) {
            return;
        }

        scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "defense-monitor");
            t.setDaemon(true);
            return t;
        });

        // 配置 IP 自动封禁参数
        ipBlocker.configureAutoBlock(
                properties.getDefense().getAutoBlockWindowSeconds(),
                properties.getDefense().getAutoBlockAttackThreshold(),
                properties.getDefense().isRepeatAttackBlock()
        );

        long windowMs = properties.getDefense().getStatsWindowMs();
        statsTask = scheduler.scheduleAtFixedRate(this::computeStats, windowMs, windowMs, TimeUnit.MILLISECONDS);
        log.info("Defense monitor started - ICMP: {} pps, SYN: {} pps, UDP: {} pps, auto-block: {}次/{}秒",
                properties.getDefense().getIcmpReplyThreshold(),
                properties.getDefense().getTcpSynThreshold(),
                properties.getDefense().getUdpThreshold(),
                properties.getDefense().getAutoBlockAttackThreshold(),
                properties.getDefense().getAutoBlockWindowSeconds());
    }

    public void stopMonitoring() {
        if (statsTask != null) {
            statsTask.cancel(false);
            statsTask = null;
        }
        if (scheduler != null) {
            scheduler.shutdownNow();
            scheduler = null;
        }
        resetCounters();
        log.info("Defense monitor stopped");
    }

    public void processPacket(PacketInfo packet) {
        // 过滤已被封禁的 IP，不参与统计和检测
        String sourceIp = packet.getSourceIp();
        if (sourceIp != null && ipBlocker.isBlocked(sourceIp)) {
            // 已被封禁的 IP 的包不计入统计，也不添加到攻击源列表
            return;
        }

        currentWindowPackets.incrementAndGet();
        currentWindowBytes.addAndGet(packet.getPacketSize());
        if (sourceIp != null) {
            currentSourceIps.add(sourceIp);
        }
        if (packet.getDestinationIp() != null) {
            currentDestinationIps.add(packet.getDestinationIp());
        }

        if (packet.getProtocol() == PacketInfo.Protocol.ICMP) {
            currentWindowIcmp.incrementAndGet();
            if (packet.getIcmpType() != null && packet.getIcmpType() == PacketInfo.ICMP_ECHO_REPLY) {
                currentWindowIcmpReply.incrementAndGet();
                if (!isLocalAddress(sourceIp)) {
                    detectedAttackSources.add(sourceIp);
                }
            }
        }

        if (packet.getProtocol() == PacketInfo.Protocol.TCP) {
            currentWindowTcp.incrementAndGet();
            if (packet.getTcpFlags() != null && packet.getTcpFlags().isSyn() && !packet.getTcpFlags().isAck()) {
                currentWindowTcpSyn.incrementAndGet();
                if (!isLocalAddress(sourceIp)) {
                    detectedAttackSources.add(sourceIp);
                }
            }
        }

        if (packet.getProtocol() == PacketInfo.Protocol.UDP) {
            currentWindowUdp.incrementAndGet();
            // 追踪 UDP 攻击源
            if (!isLocalAddress(sourceIp)) {
                detectedAttackSources.add(sourceIp);
            }
        }
    }

    private void computeStats() {
        try {
            long totalPackets = currentWindowPackets.getAndSet(0);
            long icmpPackets = currentWindowIcmp.getAndSet(0);
            long icmpReply = currentWindowIcmpReply.getAndSet(0);
            long tcpSyn = currentWindowTcpSyn.getAndSet(0);
            long tcpPackets = currentWindowTcp.getAndSet(0);
            long udpPackets = currentWindowUdp.getAndSet(0);
            long totalBytes = currentWindowBytes.getAndSet(0);
            int uniqueSrcIps = currentSourceIps.size();
            int uniqueDstIps = currentDestinationIps.size();

            currentSourceIps.clear();
            currentDestinationIps.clear();

            double bandwidthBps = totalBytes * 8.0;
            double bandwidthKBps = bandwidthBps / 1024.0;

            TrafficStats stats = TrafficStats.builder()
                    .timestamp(LocalDateTime.now())
                    .totalPackets(totalPackets)
                    .icmpPackets(icmpPackets)
                    .icmpReplyCount(icmpReply)
                    .tcpSynCount(tcpSyn)
                    .tcpPackets(tcpPackets)
                    .udpPackets(udpPackets)
                    .totalBytes(totalBytes)
                    .bandwidthBps(bandwidthBps)
                    .bandwidthKBps(bandwidthKBps)
                    .uniqueSourceIps(uniqueSrcIps)
                    .uniqueDestinationIps(uniqueDstIps)
                    .build();

            boolean attackDetected = detectAttack(stats);
            stats.setAttackDetected(attackDetected);
            currentStats = stats;

            if (statsHistory.remainingCapacity() == 0) {
                statsHistory.poll();
            }
            statsHistory.offer(stats);

            if (statsHandler != null) {
                statsHandler.accept(stats);
            }
        } catch (Exception e) {
            log.error("Failed to compute traffic stats", e);
        }
    }

    private boolean detectAttack(TrafficStats stats) {
        int icmpThreshold = properties.getDefense().getIcmpReplyThreshold();
        int synThreshold = properties.getDefense().getTcpSynThreshold();
        int udpThreshold = properties.getDefense().getUdpThreshold();
        long cooldownMs = properties.getDefense().getAlertCooldownMs();

        boolean isSmurfAttack = stats.getIcmpReplyCount() > icmpThreshold && stats.getUniqueSourceIps() > 3;
        boolean isSynFloodAttack = stats.getTcpSynCount() > synThreshold;
        boolean isUdpFloodAttack = stats.getUdpPackets() > udpThreshold;
        boolean isHighTrafficAttack = stats.getTotalPackets() > 10000 && stats.getUniqueSourceIps() <= 3;

        boolean isAttack = isSmurfAttack || isSynFloodAttack || isUdpFloodAttack || isHighTrafficAttack;

        // 清除已被封禁的攻击源，避免重复处理
        clearBlockedSources();

        // 如果没有检测到攻击，清除攻击源列表
        if (!isAttack) {
            detectedAttackSources.clear();
            return false;
        }

        // 紧急防御检测：仅在多源IP攻击时触发，单一IP攻击优先使用IP封禁
        int sourceIpThreshold = properties.getDefense().getEmergencySourceIpThreshold();
        if (properties.getDefense().isEmergencyDefense() && !emergencyModeActive
                && stats.getUniqueSourceIps() >= sourceIpThreshold) {
            checkEmergencyCondition(stats);
        }

        // 确定攻击类型（需要在冷却期检查之前，用于自动封禁）
        Alert.AlertType attackType;
        String attackDesc;
        if (isUdpFloodAttack) {
            attackType = Alert.AlertType.UDP_FLOOD;
            attackDesc = String.format("UDP Flood detected - UDP count: %d pps", stats.getUdpPackets());
        } else if (isSynFloodAttack) {
            attackType = Alert.AlertType.SYN_FLOOD;
            attackDesc = String.format("TCP SYN Flood detected - SYN count: %d pps", stats.getTcpSynCount());
        } else if (isSmurfAttack) {
            attackType = Alert.AlertType.SMURF_ATTACK;
            attackDesc = String.format("Smurf detected - ICMP reply count: %d pps", stats.getIcmpReplyCount());
        } else {
            attackType = Alert.AlertType.TRAFFIC_ANOMALY;
            attackDesc = String.format("Traffic anomaly detected - total packets: %d pps", stats.getTotalPackets());
        }

        // 检查是否在冷却期内
        if (lastAlertTime != null) {
            long elapsedMs = Duration.between(lastAlertTime, LocalDateTime.now()).toMillis();
            if (elapsedMs < cooldownMs) {
                // 冷却期内只处理未封禁的新攻击源
                if (properties.getDefense().isRepeatAttackBlock()) {
                    List<String> unblockedAttackSources = detectedAttackSources.stream()
                            .filter(ip -> !isLocalAddress(ip) && !ipBlocker.isBlocked(ip))
                            .distinct()
                            .limit(10)
                            .toList();
                    if (!unblockedAttackSources.isEmpty()) {
                        String attackTypeName = attackType.name();
                        int blockDuration = properties.getDefense().getBlockDurationMinutes();
                        List<String> autoBlockedIps = ipBlocker.checkAndAutoBlockIps(unblockedAttackSources, attackTypeName, blockDuration);
                        if (!autoBlockedIps.isEmpty()) {
                            log.warn("自动封禁 {} 个重复攻击IP: {}", autoBlockedIps.size(), autoBlockedIps);
                        }
                    }
                }
                return true;
            }
        }

        triggerAlert(stats, attackType, attackDesc);
        lastAlertTime = LocalDateTime.now();
        return true;
    }

    /**
     * 检查是否需要触发紧急防御
     * 注意：此方法仅在已检测到多源IP攻击时调用
     * 条件：极高PPS（单一IP攻击应优先使用IP封禁，不触发紧急防御）
     */
    private void checkEmergencyCondition(TrafficStats stats) {
        int ppsThreshold = properties.getDefense().getEmergencyPpsThreshold();
        long totalPps = stats.getTotalPackets();

        // 仅检测极高流量攻击（多源IP情况已在调用方判断）
        if (totalPps >= ppsThreshold) {
            String reason = String.format("极高流量攻击: %d pps, %d 个源IP", totalPps, stats.getUniqueSourceIps());
            triggerEmergencyDefense(reason, stats);
        }
    }

    /**
     * 触发紧急防御
     */
    private void triggerEmergencyDefense(String reason, TrafficStats stats) {
        emergencyModeActive = true;
        emergencyReason = reason;

        log.error("!!! 紧急防御触发 !!! 原因: {}", reason);

        // 确定防御模式
        String mode;
        if (properties.getDefense().isEmergencyStopCapture()) {
            mode = "stop";
        } else if (stats.getTcpSynCount() > properties.getDefense().getTcpSynThreshold()) {
            mode = "drop-syn";
        } else if (stats.getUdpPackets() > properties.getDefense().getUdpThreshold()) {
            mode = "drop-udp";
        } else if (stats.getIcmpPackets() > properties.getDefense().getIcmpReplyThreshold()) {
            mode = "drop-icmp";
        } else {
            mode = "established-only";
        }

        snifferService.enterEmergencyMode(mode);

        // 发送紧急告警
        if (alertHandler != null) {
            Alert emergencyAlert = Alert.builder()
                    .alertId(UUID.randomUUID().toString())
                    .timestamp(LocalDateTime.now())
                    .severity(Alert.Severity.CRITICAL)
                    .alertType(Alert.AlertType.TRAFFIC_ANOMALY)
                    .title("紧急防御模式已激活")
                    .description(reason + " | 防御模式: " + mode)
                    .sourceIp("emergency")
                    .targetIp("local")
                    .relatedStats(stats)
                    .build();
            alertHandler.accept(emergencyAlert);
        }

        // 设置自动恢复
        int recoverySeconds = properties.getDefense().getEmergencyRecoverySeconds();
        if (recoverySeconds > 0) {
            scheduleEmergencyRecovery(recoverySeconds);
        }
    }

    /**
     * 安排紧急防御自动恢复
     */
    private void scheduleEmergencyRecovery(int seconds) {
        if (emergencyRecoveryTask != null) {
            emergencyRecoveryTask.cancel(false);
        }

        emergencyRecoveryTask = scheduler.schedule(() -> {
            if (emergencyModeActive) {
                log.info("紧急防御自动恢复时间到达，检查流量状态...");
                // 检查当前流量是否恢复正常
                TrafficStats current = currentStats;
                if (current.getTotalPackets() < properties.getDefense().getEmergencyPpsThreshold() / 2
                        && current.getUniqueSourceIps() < properties.getDefense().getEmergencySourceIpThreshold() / 2) {
                    exitEmergencyMode();
                    log.info("流量已恢复正常，退出紧急防御模式");
                } else {
                    log.warn("流量仍然异常，延长紧急防御 {} 秒", seconds);
                    scheduleEmergencyRecovery(seconds);
                }
            }
        }, seconds, TimeUnit.SECONDS);
    }

    /**
     * 手动退出紧急防御模式
     */
    public void exitEmergencyMode() {
        if (!emergencyModeActive) {
            return;
        }

        emergencyModeActive = false;
        emergencyReason = null;

        snifferService.exitEmergencyMode();

        if (emergencyRecoveryTask != null) {
            emergencyRecoveryTask.cancel(false);
            emergencyRecoveryTask = null;
        }

        log.info("紧急防御模式已退出，恢复正常运行");

        // 发送恢复通知
        if (alertHandler != null) {
            Alert recoveryAlert = Alert.builder()
                    .alertId(UUID.randomUUID().toString())
                    .timestamp(LocalDateTime.now())
                    .severity(Alert.Severity.INFO)
                    .alertType(Alert.AlertType.TRAFFIC_ANOMALY)
                    .title("紧急防御模式已退出")
                    .description("系统已恢复正常流量接收")
                    .sourceIp("system")
                    .targetIp("local")
                    .build();
            alertHandler.accept(recoveryAlert);
        }
    }

    private void triggerAlert(TrafficStats stats, Alert.AlertType attackType, String attackDesc) {
        if (alertHandler == null) {
            return;
        }

        // 收集所有非本地且未封禁的攻击源 IP
        List<String> attackSourceList = detectedAttackSources.stream()
                .filter(ip -> !isLocalAddress(ip) && !ipBlocker.isBlocked(ip))
                .distinct()
                .limit(10) // 最多显示 10 个源 IP
                .toList();

        String primarySource = attackSourceList.isEmpty() ? "unknown" : attackSourceList.get(0);
        String sourceInfo = attackSourceList.isEmpty()
                ? "unknown"
                : String.join(", ", attackSourceList);

        // 构建更详细的告警描述，包含攻击源信息
        String detailedDesc = String.format("%s | 攻击源: %s | 源IP数量: %d",
                attackDesc, sourceInfo, attackSourceList.size());

        Alert alert = Alert.builder()
                .alertId(UUID.randomUUID().toString())
                .timestamp(LocalDateTime.now())
                .severity(Alert.Severity.CRITICAL)
                .alertType(attackType)
                .title("Detected " + attackType.name().replace("_", " "))
                .description(detailedDesc)
                .sourceIp(primarySource)
                .sourceIps(attackSourceList)
                .targetIp("local")
                .relatedStats(stats)
                .build();

        log.warn("Detected attack {}: {} | Sources: {}", attackType, attackDesc, sourceInfo);

        // 自动封禁重复攻击的 IP
        if (properties.getDefense().isRepeatAttackBlock() && !attackSourceList.isEmpty()) {
            String attackTypeName = attackType.name();
            int blockDuration = properties.getDefense().getBlockDurationMinutes();
            List<String> autoBlockedIps = ipBlocker.checkAndAutoBlockIps(attackSourceList, attackTypeName, blockDuration);
            if (!autoBlockedIps.isEmpty()) {
                log.warn("自动封禁 {} 个重复攻击IP: {}", autoBlockedIps.size(), autoBlockedIps);
            }
        }

        if (properties.getDefense().isAutoBlock()) {
            executeDefense(alert, stats);
        }

        if (properties.getDefense().isRateLimit()) {
            executeRateLimit(alert, stats);
        }

        alertHandler.accept(alert);
    }

    private void executeRateLimit(Alert alert, TrafficStats stats) {
        try {
            var result = rateLimitStrategy.execute(alert, stats);
            if (result.success()) {
                log.info("Rate limit applied: {}", result.message());
            } else {
                log.warn("Rate limit failed: {}", result.message());
            }
        } catch (Exception e) {
            log.error("Rate limit execution error", e);
        }
    }

    private void executeDefense(Alert alert, TrafficStats stats) {
        try {
            var result = strategyManager.executeDefense(alert, stats);
            if (result.success()) {
                log.info("Defense action succeeded: {} - {}", result.action(), result.message());
            } else {
                log.warn("Defense action failed: {}", result.message());
            }
        } catch (Exception e) {
            log.error("Defense strategy execution error", e);
        }
    }

    private void resetCounters() {
        currentWindowPackets.set(0);
        currentWindowIcmp.set(0);
        currentWindowIcmpReply.set(0);
        currentWindowTcpSyn.set(0);
        currentWindowTcp.set(0);
        currentWindowUdp.set(0);
        currentWindowBytes.set(0);
        currentSourceIps.clear();
        currentDestinationIps.clear();
        detectedAttackSources.clear();
        statsHistory.clear();
        currentStats = TrafficStats.empty();
        lastAlertTime = null;
    }

    public List<TrafficStats> getHistory(int count) {
        List<TrafficStats> result = new ArrayList<>();
        statsHistory.iterator().forEachRemaining(result::add);
        if (result.size() > count) {
            return result.subList(result.size() - count, result.size());
        }
        return result;
    }

    public int getThreshold() {
        return properties.getDefense().getIcmpReplyThreshold();
    }

    public void updateThreshold(int newThreshold) {
        properties.getDefense().setIcmpReplyThreshold(newThreshold);
        log.info("ICMP reply threshold updated to {} pps", newThreshold);
    }

    private Set<String> loadLocalIps() {
        Set<String> ips = new HashSet<>();
        try {
            var interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces != null && interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();
                var addresses = networkInterface.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress address = addresses.nextElement();
                    ips.add(address.getHostAddress());
                }
            }
        } catch (Exception e) {
            log.warn("Failed to load local IP list: {}", e.getMessage());
        }
        return ips;
    }

    private boolean isLocalAddress(String ip) {
        if (ip == null || ip.isBlank()) {
            return true;
        }
        // 检查是否是本机实际的 IP 地址
        if (localIps.contains(ip)) {
            return true;
        }

        try {
            InetAddress addr = InetAddress.getByName(ip);
            // 只排除回环地址和任意本地地址，不排除私有地址
            // 因为攻击可能来自局域网内的其他机器或伪造的私有 IP
            return addr.isAnyLocalAddress() || addr.isLoopbackAddress();
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 清除已被封禁的攻击源，避免重复处理
     */
    private void clearBlockedSources() {
        detectedAttackSources.removeIf(ip -> ipBlocker.isBlocked(ip));
    }
}
