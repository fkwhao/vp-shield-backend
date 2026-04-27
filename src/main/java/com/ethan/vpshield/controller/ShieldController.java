package com.ethan.vpshield.controller;

import com.ethan.vpshield.config.ShieldProperties;
import com.ethan.vpshield.dto.ApiResponse;
import com.ethan.vpshield.dto.AttackRequest;
import com.ethan.vpshield.dto.SystemStatus;
import com.ethan.vpshield.model.Alert;
import com.ethan.vpshield.model.NetworkInterface;
import com.ethan.vpshield.model.TrafficStats;
import com.ethan.vpshield.service.AttackEngine;
import com.ethan.vpshield.service.DefenseMonitor;
import com.ethan.vpshield.service.LoopbackTestService;
import com.ethan.vpshield.service.SnifferService;
import com.ethan.vpshield.service.defense.DefenseStrategyManager;
import com.ethan.vpshield.service.defense.IpBlocker;
import com.ethan.vpshield.service.defense.RateLimitStrategy;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.NotOpenException;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 网络安全监控 API 控制器
 * 提供 REST 接口供 Electron 前端调用
 */
@Slf4j
@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class ShieldController {

    private final SnifferService snifferService;
    private final AttackEngine attackEngine;
    private final DefenseMonitor defenseMonitor;
    private final TrafficWebSocketHandler webSocketHandler;
    private final LoopbackTestService loopbackTestService;
    private final IpBlocker ipBlocker;
    private final DefenseStrategyManager strategyManager;
    private final RateLimitStrategy rateLimitStrategy;

    // ==================== 网络接口相关 ====================

    /**
     * 获取可用网络接口列表
     * GET /api/v1/interfaces
     */
    @GetMapping("/interfaces")
    public ApiResponse<List<NetworkInterface>> getInterfaces() {
        List<NetworkInterface> interfaces = snifferService.getAvailableInterfaces();
        return ApiResponse.success(interfaces);
    }

    // ==================== 抓包控制 ====================

    /**
     * 启动抓包
     * POST /api/v1/capture/start
     */
    @PostMapping("/capture/start")
    public ApiResponse<String> startCapture(@RequestBody(required = false) Map<String, String> request) {
        if (snifferService.isCapturing()) {
            return ApiResponse.error("抓包已在运行中");
        }

        String interfaceName = request != null ? request.get("interfaceName") : null;

        // 启动防御监控
        defenseMonitor.startMonitoring(
                stats -> webSocketHandler.broadcastStats(stats),
                alert -> webSocketHandler.broadcastAlert(alert)
        );

        // 启动抓包
        snifferService.startCapture(
                interfaceName,
                defenseMonitor::processPacket,
                error -> log.error("抓包错误", error)
        );

        return ApiResponse.success("抓包已启动");
    }

    /**
     * 停止抓包
     * POST /api/v1/capture/stop
     */
    @PostMapping("/capture/stop")
    public ApiResponse<String> stopCapture() throws NotOpenException {
        snifferService.stopCapture();
        defenseMonitor.stopMonitoring();
        return ApiResponse.success("抓包已停止");
    }

    /**
     * 获取抓包状态
     * GET /api/v1/capture/status
     */
    @GetMapping("/capture/status")
    public ApiResponse<Boolean> getCaptureStatus() {
        return ApiResponse.success(snifferService.isCapturing());
    }

    // ==================== 攻击模拟 ====================

    /**
     * 启动 Smurf 攻击模拟
     * POST /api/v1/attack/start
     */
    @PostMapping("/attack/start")
    public ApiResponse<String> startAttack(@Valid @RequestBody AttackRequest request) {
        if (attackEngine.isAttacking()) {
            return ApiResponse.error("攻击已在进行中");
        }

        log.warn("收到攻击请求 - 目标: {}, 广播: {}, 包数: {}",
                request.getVictimIp(), request.getBroadcastIp(), request.getPacketCount());

        attackEngine.startSmurfAttack(
                request.getVictimIp(),
                request.getBroadcastIp(),
                request.getPacketCount(),
                request.getInterfaceName()
        );

        return ApiResponse.success("攻击模拟已启动");
    }

    /**
     * 停止攻击
     * POST /api/v1/attack/stop
     */
    @PostMapping("/attack/stop")
    public ApiResponse<String> stopAttack() {
        attackEngine.stopAttack();
        return ApiResponse.success("攻击已停止");
    }

    /**
     * 获取攻击状态
     * GET /api/v1/attack/status
     */
    @GetMapping("/attack/status")
    public ApiResponse<Boolean> getAttackStatus() {
        return ApiResponse.success(attackEngine.isAttacking());
    }

    // ==================== 回环测试 ====================

    /**
     * 启动回环测试
     * POST /api/v1/test/start
     */
    @PostMapping("/test/start")
    public ApiResponse<String> startLoopbackTest(@RequestBody(required = false) Map<String, Integer> request) {
        if (loopbackTestService.isTesting()) {
            return ApiResponse.error("测试已在运行中");
        }

        int packetCount = request != null && request.get("packetCount") != null
                ? request.get("packetCount") : 200;
        int sourceIpCount = request != null && request.get("sourceIpCount") != null
                ? request.get("sourceIpCount") : 5;

        // 确保防御监控在运行
        if (!snifferService.isCapturing()) {
            defenseMonitor.startMonitoring(
                    stats -> webSocketHandler.broadcastStats(stats),
                    alert -> webSocketHandler.broadcastAlert(alert)
            );
        }

        loopbackTestService.startTest(packetCount, sourceIpCount);
        return ApiResponse.success("回环测试已启动");
    }

    /**
     * 停止回环测试
     * POST /api/v1/test/stop
     */
    @PostMapping("/test/stop")
    public ApiResponse<String> stopLoopbackTest() {
        loopbackTestService.stopTest();
        return ApiResponse.success("回环测试已停止");
    }

    /**
     * 获取测试状态
     * GET /api/v1/test/status
     */
    @GetMapping("/test/status")
    public ApiResponse<Boolean> getTestStatus() {
        return ApiResponse.success(loopbackTestService.isTesting());
    }

    // ==================== 封禁管理 ====================

    /**
     * 获取被封禁的 IP 列表
     * GET /api/v1/block/list
     */
    @GetMapping("/block/list")
    public ApiResponse<List<Map<String, Object>>> getBlockedIps() {
        List<Map<String, Object>> result = ipBlocker.getBlockedIps().entrySet().stream()
                .map(entry -> {
                    Map<String, Object> map = new HashMap<>();
                    map.put("ip", entry.getValue().ip());
                    map.put("reason", entry.getValue().reason());
                    map.put("blockedAt", entry.getValue().blockedAt());
                    map.put("expiresAt", entry.getValue().expiresAt());
                    return map;
                })
                .toList();
        return ApiResponse.success(result);
    }

    /**
     * 解封指定 IP
     * DELETE /api/v1/block/{ip}
     */
    @DeleteMapping("/block/{ip}")
    public ApiResponse<String> unblockIp(@PathVariable String ip) {
        ipBlocker.unblock(ip);
        return ApiResponse.success("IP 已解封: " + ip);
    }

    /**
     * 清空所有封禁
     * POST /api/v1/block/clear
     */
    @PostMapping("/block/clear")
    public ApiResponse<String> clearAllBlocks() {
        ipBlocker.clearAll();
        return ApiResponse.success("所有封禁已清除");
    }

    /**
     * 清理防火墙残留规则（同步内存与防火墙）
     * POST /api/v1/block/sync
     */
    @PostMapping("/block/sync")
    public ApiResponse<String> syncFirewallRules() {
        ipBlocker.cleanupAllFirewallRules();
        // 同时禁用限速
        rateLimitStrategy.disableRateLimit();
        return ApiResponse.success("防火墙规则已清理，限速已禁用");
    }

    /**
     * 完全重置防御状态
     * POST /api/v1/defense/reset
     */
    @PostMapping("/defense/reset")
    public ApiResponse<String> resetDefense() {
        // 清空封禁列表
        ipBlocker.clearAll();
        // 清理防火墙规则
        ipBlocker.cleanupAllFirewallRules();
        // 禁用限速
        rateLimitStrategy.disableRateLimit();
        // 清空攻击源记录
        defenseMonitor.getDetectedAttackSources().clear();

        return ApiResponse.success("防御状态已完全重置");
    }

    // ==================== 限速管理 ====================

    /**
     * 获取限速状态
     * GET /api/v1/ratelimit/status
     */
    @GetMapping("/ratelimit/status")
    public ApiResponse<Boolean> getRateLimitStatus() {
        return ApiResponse.success(rateLimitStrategy.isRateLimitEnabled());
    }

    /**
     * 手动禁用限速（恢复正常）
     * POST /api/v1/ratelimit/disable
     */
    @PostMapping("/ratelimit/disable")
    public ApiResponse<String> disableRateLimit() {
        rateLimitStrategy.disableRateLimit();
        return ApiResponse.success("限速已禁用，流量恢复正常");
    }

    // ==================== 流量统计 ====================

    /**
     * 获取当前流量统计
     * GET /api/v1/stats/current
     */
    @GetMapping("/stats/current")
    public ApiResponse<TrafficStats> getCurrentStats() {
        return ApiResponse.success(defenseMonitor.getCurrentStats());
    }

    /**
     * 获取历史流量统计
     * GET /api/v1/stats/history?count=30
     */
    @GetMapping("/stats/history")
    public ApiResponse<List<TrafficStats>> getStatsHistory(
            @RequestParam(defaultValue = "30") int count) {
        return ApiResponse.success(defenseMonitor.getHistory(count));
    }

    // ==================== 防御配置 ====================

    /**
     * 获取检测阈值
     * GET /api/v1/defense/threshold
     */
    @GetMapping("/defense/threshold")
    public ApiResponse<Integer> getThreshold() {
        return ApiResponse.success(defenseMonitor.getThreshold());
    }

    /**
     * 更新检测阈值
     * PUT /api/v1/defense/threshold
     */
    @PutMapping("/defense/threshold")
    public ApiResponse<String> updateThreshold(@RequestBody Map<String, Integer> request) {
        Integer threshold = request.get("threshold");
        if (threshold == null || threshold < 1) {
            return ApiResponse.error("无效的阈值");
        }
        defenseMonitor.updateThreshold(threshold);
        return ApiResponse.success("阈值已更新为: " + threshold);
    }

    /**
     * 获取检测到的攻击源
     * GET /api/v1/defense/attack-sources
     */
    @GetMapping("/defense/attack-sources")
    public ApiResponse<List<String>> getAttackSources() {
        return ApiResponse.success(List.copyOf(defenseMonitor.getDetectedAttackSources()));
    }

    /**
     * 获取防御策略信息
     * GET /api/v1/defense/strategies
     */
    @GetMapping("/defense/strategies")
    public ApiResponse<Map<Alert.AlertType, String>> getDefenseStrategies() {
        return ApiResponse.success(strategyManager.getStrategyInfo());
    }

    // ==================== 系统配置 ====================

    private final ShieldProperties shieldProperties;

    /**
     * 获取完整配置
     * GET /api/v1/config
     */
    @GetMapping("/config")
    public ApiResponse<ShieldProperties> getConfig() {
        return ApiResponse.success(shieldProperties);
    }

    /**
     * 更新配置（部分更新）
     * PUT /api/v1/config
     */
    @PutMapping("/config")
    public ApiResponse<String> updateConfig(@RequestBody Map<String, Object> updates) {
        try {
            // 更新抓包配置
            if (updates.containsKey("capture")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> capture = (Map<String, Object>) updates.get("capture");
                ShieldProperties.CaptureConfig captureConfig = shieldProperties.getCapture();
                if (capture.containsKey("promiscuous")) {
                    captureConfig.setPromiscuous((Boolean) capture.get("promiscuous"));
                }
                if (capture.containsKey("bufferSize")) {
                    captureConfig.setBufferSize(((Number) capture.get("bufferSize")).intValue());
                }
                if (capture.containsKey("readTimeout")) {
                    captureConfig.setReadTimeout(((Number) capture.get("readTimeout")).intValue());
                }
            }

            // 更新防御配置
            if (updates.containsKey("defense")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> defense = (Map<String, Object>) updates.get("defense");
                ShieldProperties.DefenseConfig defenseConfig = shieldProperties.getDefense();
                if (defense.containsKey("icmpReplyThreshold")) {
                    defenseConfig.setIcmpReplyThreshold(((Number) defense.get("icmpReplyThreshold")).intValue());
                }
                if (defense.containsKey("tcpSynThreshold")) {
                    defenseConfig.setTcpSynThreshold(((Number) defense.get("tcpSynThreshold")).intValue());
                }
                if (defense.containsKey("udpThreshold")) {
                    defenseConfig.setUdpThreshold(((Number) defense.get("udpThreshold")).intValue());
                }
                if (defense.containsKey("autoBlock")) {
                    defenseConfig.setAutoBlock((Boolean) defense.get("autoBlock"));
                }
                if (defense.containsKey("blockDurationMinutes")) {
                    defenseConfig.setBlockDurationMinutes(((Number) defense.get("blockDurationMinutes")).intValue());
                }
                if (defense.containsKey("rateLimit")) {
                    defenseConfig.setRateLimit((Boolean) defense.get("rateLimit"));
                }
                if (defense.containsKey("rateLimitRecoverySeconds")) {
                    defenseConfig.setRateLimitRecoverySeconds(((Number) defense.get("rateLimitRecoverySeconds")).intValue());
                }
            }

            // 更新攻击配置
            if (updates.containsKey("attack")) {
                @SuppressWarnings("unchecked")
                Map<String, Object> attack = (Map<String, Object>) updates.get("attack");
                ShieldProperties.AttackConfig attackConfig = shieldProperties.getAttack();
                if (attack.containsKey("defaultPacketCount")) {
                    attackConfig.setDefaultPacketCount(((Number) attack.get("defaultPacketCount")).intValue());
                }
                if (attack.containsKey("packetIntervalMs")) {
                    attackConfig.setPacketIntervalMs(((Number) attack.get("packetIntervalMs")).longValue());
                }
            }

            log.info("配置已更新: {}", updates.keySet());
            return ApiResponse.success("配置已更新");
        } catch (Exception e) {
            log.error("更新配置失败", e);
            return ApiResponse.error("更新配置失败: " + e.getMessage());
        }
    }

    // ==================== 系统状态 ====================

    /**
     * 获取系统整体状态
     * GET /api/v1/status
     */
    @GetMapping("/status")
    public ApiResponse<SystemStatus> getSystemStatus() {
        SystemStatus status = SystemStatus.builder()
                .capturing(snifferService.isCapturing())
                .attacking(attackEngine.isAttacking())
                .packetsSent(attackEngine.getPacketsSent().get())
                .attackSourceCount(defenseMonitor.getDetectedAttackSources().size())
                .icmpThreshold(defenseMonitor.getThreshold())
                .build();
        return ApiResponse.success(status);
    }

    // ==================== 紧急防御 ====================

    /**
     * 获取紧急防御状态
     * GET /api/v1/emergency/status
     */
    @GetMapping("/emergency/status")
    public ApiResponse<Map<String, Object>> getEmergencyStatus() {
        Map<String, Object> status = new HashMap<>();
        status.put("emergencyModeActive", defenseMonitor.isEmergencyModeActive());
        status.put("emergencyReason", defenseMonitor.getEmergencyReason());
        status.put("snifferEmergencyMode", snifferService.isEmergencyMode());
        status.put("currentFilter", snifferService.getCurrentFilter());
        status.put("config", Map.of(
                "enabled", shieldProperties.getDefense().isEmergencyDefense(),
                "sourceIpThreshold", shieldProperties.getDefense().getEmergencySourceIpThreshold(),
                "ppsThreshold", shieldProperties.getDefense().getEmergencyPpsThreshold(),
                "stopCapture", shieldProperties.getDefense().isEmergencyStopCapture(),
                "recoverySeconds", shieldProperties.getDefense().getEmergencyRecoverySeconds()
        ));
        return ApiResponse.success(status);
    }

    /**
     * 手动触发紧急防御
     * POST /api/v1/emergency/trigger
     */
    @PostMapping("/emergency/trigger")
    public ApiResponse<String> triggerEmergency(@RequestBody(required = false) Map<String, String> request) {
        String mode = request != null ? request.getOrDefault("mode", "established-only") : "established-only";

        log.warn("手动触发紧急防御模式: {}", mode);

        boolean success = snifferService.enterEmergencyMode(mode);

        if (success) {
            return ApiResponse.success("紧急防御模式已激活: " + mode);
        } else {
            return ApiResponse.error("紧急防御激活失败");
        }
    }

    /**
     * 退出紧急防御模式
     * POST /api/v1/emergency/recover
     */
    @PostMapping("/emergency/recover")
    public ApiResponse<String> recoverFromEmergency() {
        log.info("手动退出紧急防御模式");
        defenseMonitor.exitEmergencyMode();

        return ApiResponse.success("已退出紧急防御模式，恢复正常运行");
    }

    /**
     * 动态设置抓包过滤器
     * PUT /api/v1/capture/filter
     */
    @PutMapping("/capture/filter")
    public ApiResponse<String> setCaptureFilter(@RequestBody Map<String, String> request) {
        String filter = request.get("filter");
        if (filter == null || filter.isBlank()) {
            return ApiResponse.error("过滤器不能为空");
        }

        if (!snifferService.isCapturing()) {
            return ApiResponse.error("抓包未运行");
        }

        log.info("动态设置BPF过滤器: {}", filter);
        // 通过紧急模式接口设置过滤器
        snifferService.enterEmergencyMode(filter.equals("ip") ? "none" : "custom");

        return ApiResponse.success("过滤器已更新: " + filter);
    }

    /**
     * 健康检查
     * GET /api/v1/health
     */
    @GetMapping("/health")
    public ApiResponse<String> health() {
        return ApiResponse.success("OK");
    }
}