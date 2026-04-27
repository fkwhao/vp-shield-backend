package com.ethan.vpshield.service.defense;

import jakarta.annotation.PostConstruct;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.time.LocalDateTime;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 * IP 封禁管理器
 * 管理被封禁的 IP 地址列表，支持基于攻击频率的自动封禁
 */
@Slf4j
@Component
public class IpBlocker {

    /**
     * 封禁记录
     */
    @Getter
    private final Map<String, BlockRecord> blockedIps = new ConcurrentHashMap<>();

    /**
     * IP 攻击记录追踪（用于自动封禁）
     * Key: IP 地址, Value: 攻击时间戳队列
     */
    private final Map<String, Deque<LocalDateTime>> attackHistory = new ConcurrentHashMap<>();

    /**
     * 自动封禁配置
     */
    private int autoBlockWindowSeconds = 30;
    private int autoBlockAttackThreshold = 3;
    private boolean repeatAttackBlockEnabled = true;

    /**
     * 服务启动时清理所有 VP-Shield 防火墙规则
     * 避免重启后内存列表与防火墙不同步
     */
    @PostConstruct
    public void init() {
        log.info("初始化 IP 封禁管理器，清理残留防火墙规则...");
        cleanupAllFirewallRules();
    }

    /**
     * 封禁 IP
     *
     * @param ip        要封禁的 IP
     * @param reason    封禁原因
     * @param durationMinutes 封禁时长（分钟），0 表示永久
     */
    public void block(String ip, String reason, int durationMinutes) {
        BlockRecord record = new BlockRecord(
                ip,
                reason,
                LocalDateTime.now(),
                durationMinutes > 0 ? LocalDateTime.now().plusMinutes(durationMinutes) : null
        );

        blockedIps.put(ip, record);
        log.warn("IP 已封禁: {} - 原因: {}, 时长: {} 分钟", ip, reason, durationMinutes > 0 ? durationMinutes : "永久");

        // TODO: 实际封禁逻辑（调用防火墙等）
        executeBlock(ip);
    }

    /**
     * 解封 IP
     */
    public void unblock(String ip) {
        BlockRecord removed = blockedIps.remove(ip);
        if (removed != null) {
            log.info("IP 已解封: {}", ip);
            // TODO: 实际解封逻辑
            executeUnblock(ip);
        }
    }

    /**
     * 检查 IP 是否被封禁
     */
    public boolean isBlocked(String ip) {
        BlockRecord record = blockedIps.get(ip);
        if (record == null) {
            return false;
        }

        // 检查是否过期
        if (record.expiresAt() != null && LocalDateTime.now().isAfter(record.expiresAt())) {
            blockedIps.remove(ip);
            log.info("IP 封禁已过期，自动解封: {}", ip);
            return false;
        }

        return true;
    }

    /**
     * 获取所有被封禁的 IP
     */
    public Set<String> getBlockedIpSet() {
        // 清理过期的封禁
        blockedIps.entrySet().removeIf(entry -> {
            if (entry.getValue().expiresAt() != null && LocalDateTime.now().isAfter(entry.getValue().expiresAt())) {
                log.info("IP 封禁已过期: {}", entry.getKey());
                return true;
            }
            return false;
        });

        return new HashSet<>(blockedIps.keySet());
    }

    /**
     * 清空所有封禁
     */
    public void clearAll() {
        for (String ip : new HashSet<>(blockedIps.keySet())) {
            executeUnblock(ip);
        }
        blockedIps.clear();
        log.info("所有 IP 封禁已清除");
    }

    /**
     * 清理所有 VP-Shield 创建的防火墙规则
     * 用于服务启动时同步状态
     */
    public void cleanupAllFirewallRules() {
        String os = System.getProperty("os.name").toLowerCase();

        if (os.contains("win")) {
            try {
                // 直接删除所有 VP-Shield-Block 开头的规则
                // 通过遍历可能的 IP 格式来清理
                Process process = Runtime.getRuntime().exec(new String[]{
                    "cmd", "/c", "netsh", "advfirewall", "firewall", "show", "rule", "name=all"
                });
                BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream())
                );

                List<String> rulesToDelete = new ArrayList<>();
                String line;
                while ((line = reader.readLine()) != null) {
                    if (line.contains("VP-Shield-Block-")) {
                        // 提取规则名称 - 格式通常是 "Rule Name: VP-Shield-Block-x-x-x-x"
                        int nameIndex = line.indexOf("VP-Shield-Block-");
                        if (nameIndex != -1) {
                            String ruleName = line.substring(nameIndex).trim();
                            // 清理可能的尾部空格或额外字符
                            ruleName = ruleName.split("\\s+")[0];
                            rulesToDelete.add(ruleName);
                        }
                    }
                }
                process.waitFor();

                // 删除找到的规则
                for (String ruleName : rulesToDelete) {
                    try {
                        Process deleteProcess = Runtime.getRuntime().exec(new String[]{
                            "cmd", "/c", "netsh", "advfirewall", "firewall", "delete", "rule",
                            "name=\"" + ruleName + "\""
                        });
                        int exitCode = deleteProcess.waitFor();
                        if (exitCode == 0) {
                            log.info("清理防火墙规则: {}", ruleName);
                        }
                    } catch (Exception e) {
                        log.warn("删除规则 {} 失败: {}", ruleName, e.getMessage());
                    }
                }
                log.info("清理完成，共删除 {} 条 VP-Shield 防火墙规则", rulesToDelete.size());
            } catch (Exception e) {
                log.warn("清理防火墙规则失败: {}", e.getMessage());
            }
        } else if (os.contains("linux")) {
            // Linux 下清理 iptables 规则需要更复杂的逻辑
            log.info("Linux 系统请手动检查 iptables 规则");
        }
    }

    /**
     * 执行实际封禁（调用系统防火墙）
     * Windows: netsh advfirewall
     * Linux: iptables
     */
    private void executeBlock(String ip) {
        String os = System.getProperty("os.name").toLowerCase();

        try {
            if (os.contains("win")) {
                // Windows 防火墙规则 - 使用 cmd /c 执行
                String ruleName = "VP-Shield-Block-" + ip.replace(".", "-");
                String[] command = {
                    "cmd", "/c",
                    "netsh", "advfirewall", "firewall", "add", "rule",
                    "name=\"" + ruleName + "\"",
                    "dir=in",
                    "action=block",
                    "remoteip=" + ip
                };
                Process process = Runtime.getRuntime().exec(command);
                int exitCode = process.waitFor();
                if (exitCode == 0) {
                    log.info("Windows 防火墙封禁成功: {} -> {}", ruleName, ip);
                } else {
                    log.error("Windows 防火墙封禁失败，退出码: {}", exitCode);
                    // 读取错误输出
                    try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                        String line;
                        while ((line = reader.readLine()) != null) {
                            log.error("错误: {}", line);
                        }
                    }
                }
            } else if (os.contains("linux")) {
                // Linux iptables
                Process process = Runtime.getRuntime().exec(new String[]{"sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"});
                int exitCode = process.waitFor();
                if (exitCode == 0) {
                    log.info("iptables 封禁成功: {}", ip);
                } else {
                    log.error("iptables 封禁失败，退出码: {}", exitCode);
                }
            } else {
                log.warn("不支持的操作系统，无法执行实际封禁: {}", os);
            }
        } catch (Exception e) {
            log.error("执行防火墙封禁失败: {}", e.getMessage(), e);
        }
    }

    /**
     * 执行实际解封
     */
    private void executeUnblock(String ip) {
        String os = System.getProperty("os.name").toLowerCase();

        try {
            if (os.contains("win")) {
                String ruleName = "VP-Shield-Block-" + ip.replace(".", "-");
                String[] command = {
                    "cmd", "/c",
                    "netsh", "advfirewall", "firewall", "delete", "rule",
                    "name=\"" + ruleName + "\""
                };
                Process process = Runtime.getRuntime().exec(command);
                int exitCode = process.waitFor();
                if (exitCode == 0) {
                    log.info("Windows 防火墙解封成功: {}", ruleName);
                } else {
                    log.debug("Windows 防火墙解封（规则可能不存在），退出码: {}", exitCode);
                }
            } else if (os.contains("linux")) {
                Process process = Runtime.getRuntime().exec(new String[]{"sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"});
                int exitCode = process.waitFor();
                if (exitCode == 0) {
                    log.info("iptables 解封成功: {}", ip);
                } else {
                    log.debug("iptables 解封（规则可能不存在），退出码: {}", exitCode);
                }
            }
        } catch (Exception e) {
            log.error("执行防火墙解封失败: {}", e.getMessage(), e);
        }
    }

    /**
     * 封禁记录
     */
    public record BlockRecord(
            String ip,
            String reason,
            LocalDateTime blockedAt,
            LocalDateTime expiresAt
    ) {}

    /**
     * 配置自动封禁参数
     */
    public void configureAutoBlock(int windowSeconds, int threshold, boolean enabled) {
        this.autoBlockWindowSeconds = windowSeconds;
        this.autoBlockAttackThreshold = threshold;
        this.repeatAttackBlockEnabled = enabled;
        log.info("自动封禁配置: 窗口={}秒, 阈值={}次, 启用={}", windowSeconds, threshold, enabled);
    }

    /**
     * 记录一次攻击并检查是否需要自动封禁
     *
     * @param ip         攻击源 IP
     * @param attackType 攻击类型
     * @param blockDurationMinutes 封禁时长（分钟）
     * @return true 如果本次调用触发了新的封禁（不包括已封禁的 IP）
     */
    public boolean recordAttackAndCheckAutoBlock(String ip, String attackType, int blockDurationMinutes) {
        if (!repeatAttackBlockEnabled || ip == null || ip.isBlank()) {
            return false;
        }

        // 已被封禁的 IP 直接返回 false，避免重复日志
        if (isBlocked(ip)) {
            return false;
        }

        LocalDateTime now = LocalDateTime.now();
        LocalDateTime windowStart = now.minusSeconds(autoBlockWindowSeconds);

        // 获取或创建该 IP 的攻击记录队列
        Deque<LocalDateTime> attacks = attackHistory.computeIfAbsent(ip, k -> new ConcurrentLinkedDeque<>());

        // 移除过期的记录（超出时间窗口的）
        while (!attacks.isEmpty() && attacks.peekFirst().isBefore(windowStart)) {
            attacks.pollFirst();
        }

        // 添加当前攻击记录
        attacks.addLast(now);

        int attackCount = attacks.size();

        // 检查是否达到阈值
        if (attackCount >= autoBlockAttackThreshold) {
            String reason = String.format("自动封禁: %d秒内%d次%s攻击",
                    autoBlockWindowSeconds, attackCount, attackType);
            block(ip, reason, blockDurationMinutes);
            // 清除该 IP 的攻击记录
            attackHistory.remove(ip);
            return true;
        }

        return false;
    }

    /**
     * 批量检查多个 IP 的自动封禁
     *
     * @param ips       攻击源 IP 列表
     * @param attackType 攻击类型
     * @param blockDurationMinutes 封禁时长
     * @return 被自动封禁的 IP 列表
     */
    public List<String> checkAndAutoBlockIps(List<String> ips, String attackType, int blockDurationMinutes) {
        List<String> blockedIps = new ArrayList<>();
        for (String ip : ips) {
            if (recordAttackAndCheckAutoBlock(ip, attackType, blockDurationMinutes)) {
                blockedIps.add(ip);
            }
        }
        return blockedIps;
    }

    /**
     * 清理过期的攻击记录
     */
    public void cleanupExpiredAttackHistory() {
        LocalDateTime windowStart = LocalDateTime.now().minusSeconds(autoBlockWindowSeconds);
        attackHistory.entrySet().removeIf(entry -> {
            // 移除过期的记录
            while (!entry.getValue().isEmpty() && entry.getValue().peekFirst().isBefore(windowStart)) {
                entry.getValue().pollFirst();
            }
            // 如果队列为空，移除整个条目
            return entry.getValue().isEmpty();
        });
    }

    /**
     * 获取 IP 的当前攻击次数（用于调试/显示）
     */
    public int getAttackCount(String ip) {
        Deque<LocalDateTime> attacks = attackHistory.get(ip);
        if (attacks == null) {
            return 0;
        }
        LocalDateTime windowStart = LocalDateTime.now().minusSeconds(autoBlockWindowSeconds);
        return (int) attacks.stream().filter(t -> t.isAfter(windowStart)).count();
    }
}