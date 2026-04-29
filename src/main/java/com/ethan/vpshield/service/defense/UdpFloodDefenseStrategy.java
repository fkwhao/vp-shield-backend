package com.ethan.vpshield.service.defense;

import com.ethan.vpshield.config.ShieldProperties;
import com.ethan.vpshield.model.Alert;
import com.ethan.vpshield.model.TrafficStats;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * UDP Flood 攻击防御策略
 *
 * 防御措施：
 * 1. 封禁攻击源 IP
 * 2. 可选：限制 UDP 流量
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class UdpFloodDefenseStrategy implements DefenseStrategy {

    private final IpBlocker ipBlocker;
    private final ShieldProperties properties;

    @Override
    public String getName() {
        return "UDP Flood 攻击防御";
    }

    @Override
    public Alert.AlertType getSupportedAttackType() {
        return Alert.AlertType.UDP_FLOOD;
    }

    /**
     * 执行 UDP Flood 攻击防御
     *
     * @param alert 告警信息
     * @param stats 流量统计
     * @return 防御结果
     */
    @Override
    public DefenseResult execute(Alert alert, TrafficStats stats) {
        log.warn("执行 UDP Flood 攻击防御 - 攻击源: {}", alert.getSourceIps());

        int blockDuration = properties.getDefense().getBlockDurationMinutes();
        boolean autoBlock = properties.getDefense().isAutoBlock();

        if (!autoBlock) {
            return DefenseResult.failure("自动封禁未启用");
        }

        // 封禁所有攻击源 IP
        java.util.List<String> sourceIps = alert.getSourceIps();
        if (sourceIps == null || sourceIps.isEmpty()) {
            String sourceIp = alert.getSourceIp();
            if (sourceIp != null && !sourceIp.equals("unknown")) {
                sourceIps = java.util.List.of(sourceIp);
            }
        }

        if (sourceIps == null || sourceIps.isEmpty()) {
            return DefenseResult.failure("无法识别攻击源 IP");
        }

        java.util.List<String> blockedIps = new java.util.ArrayList<>();
        for (String ip : sourceIps) {
            if (ip != null && !ip.equals("unknown") && !ipBlocker.isBlocked(ip)) {
                ipBlocker.block(ip, "UDP Flood 攻击源", blockDuration);
                blockedIps.add(ip);
            }
        }

        boolean hasPermission = canExecute();
        if (!hasPermission) {
            log.warn("无管理员权限，仅记录封禁，未执行防火墙规则");
        }

        if (blockedIps.isEmpty()) {
            return DefenseResult.failure("所有攻击源 IP 已被封禁");
        }

        return DefenseResult.success(
                "BLOCK_IP",
                String.format("已封禁 %d 个 UDP Flood 攻击源 IP，时长 %d 分钟", blockedIps.size(), blockDuration),
                blockedIps.toArray(new String[0])
        );
    }

    /**
     * 检查是否有执行权限
     *
     * @return true 如果有管理员/root权限
     */
    @Override
    public boolean canExecute() {
        String os = System.getProperty("os.name").toLowerCase();

        if (os.contains("win")) {
            try {
                Process process = Runtime.getRuntime().exec("net session");
                process.waitFor();
                return process.exitValue() == 0;
            } catch (Exception e) {
                log.warn("无法检查管理员权限: {}", e.getMessage());
                return false;
            }
        } else if (os.contains("linux")) {
            return "root".equals(System.getProperty("user.name"));
        }

        return false;
    }
}
