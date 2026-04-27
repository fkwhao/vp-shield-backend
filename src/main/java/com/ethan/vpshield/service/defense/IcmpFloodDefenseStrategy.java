package com.ethan.vpshield.service.defense;

import com.ethan.vpshield.config.ShieldProperties;
import com.ethan.vpshield.model.Alert;
import com.ethan.vpshield.model.TrafficStats;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

/**
 * ICMP Flood 攻击防御策略
 *
 * 防御措施：
 * 1. 限制 ICMP 流量速率
 * 2. 封禁高频率发送 ICMP 的源 IP
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class IcmpFloodDefenseStrategy implements DefenseStrategy {

    private final IpBlocker ipBlocker;
    private final ShieldProperties properties;

    @Override
    public String getName() {
        return "ICMP Flood 防御";
    }

    @Override
    public Alert.AlertType getSupportedAttackType() {
        return Alert.AlertType.ICMP_FLOOD;
    }

    @Override
    public DefenseResult execute(Alert alert, TrafficStats stats) {
        log.warn("执行 ICMP Flood 防御 - 攻击源: {}", alert.getSourceIp());

        int blockDuration = properties.getDefense().getBlockDurationMinutes();
        boolean autoBlock = properties.getDefense().isAutoBlock();

        if (!autoBlock) {
            return DefenseResult.failure("自动封禁未启用");
        }

        String sourceIp = alert.getSourceIp();
        if (sourceIp != null && !sourceIp.equals("unknown")) {
            ipBlocker.block(sourceIp, "ICMP Flood 攻击源", blockDuration);

            boolean hasPermission = canExecute();
            if (!hasPermission) {
                log.warn("无管理员权限，仅记录封禁，未执行防火墙规则");
            }

            return DefenseResult.success(
                    "BLOCK_IP",
                    String.format("已封禁 ICMP Flood 攻击源: %s", sourceIp),
                    sourceIp
            );
        }

        return DefenseResult.failure("无法识别攻击源 IP");
    }

    @Override
    public boolean canExecute() {
        // 与 SmurfDefenseStrategy 相同的权限检查
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("win")) {
            try {
                Process process = Runtime.getRuntime().exec("net session");
                process.waitFor();
                return process.exitValue() == 0;
            } catch (Exception e) {
                return false;
            }
        } else if (os.contains("linux")) {
            return "root".equals(System.getProperty("user.name"));
        }
        return false;
    }
}