package com.ethan.vpshield.service.defense;

import com.ethan.vpshield.config.ShieldProperties;
import com.ethan.vpshield.model.Alert;
import com.ethan.vpshield.model.TrafficStats;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * Smurf 攻击防御策略
 *
 * 防御措施：
 * 1. 封禁攻击源 IP（发送 ICMP Reply 的主机）
 * 2. 可选：限制 ICMP 流量
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class SmurfDefenseStrategy implements DefenseStrategy {

    private final IpBlocker ipBlocker;
    private final ShieldProperties properties;

    @Override
    public String getName() {
        return "Smurf 攻击防御";
    }

    @Override
    public Alert.AlertType getSupportedAttackType() {
        return Alert.AlertType.SMURF_ATTACK;
    }

    /**
     * 执行 Smurf 攻击防御
     *
     * @param alert 告警信息
     * @param stats 流量统计
     * @return 防御结果
     */
    @Override
    public DefenseResult execute(Alert alert, TrafficStats stats) {
        log.warn("执行 Smurf 攻击防御 - 攻击源: {}", alert.getSourceIp());

        // 获取配置
        int blockDuration = properties.getDefense().getBlockDurationMinutes();
        boolean autoBlock = properties.getDefense().isAutoBlock();

        if (!autoBlock) {
            return DefenseResult.failure("自动封禁未启用");
        }

        // 封禁攻击源
        String sourceIp = alert.getSourceIp();
        if (sourceIp != null && !sourceIp.equals("unknown")) {
            ipBlocker.block(sourceIp, "Smurf 攻击源", blockDuration);

            boolean hasPermission = canExecute();
            if (!hasPermission) {
                log.warn("无管理员权限，仅记录封禁，未执行防火墙规则");
            }

            return DefenseResult.success(
                    "BLOCK_IP",
                    String.format("已封禁攻击源 IP: %s，时长 %d 分钟", sourceIp, blockDuration),
                    sourceIp
            );
        }

        return DefenseResult.failure("无法识别攻击源 IP");
    }

    /**
     * 检查是否有执行权限
     *
     * @return true 如果有管理员/root权限
     */
    @Override
    public boolean canExecute() {
        // 检查是否有管理员权限（Windows）
        // 或 root 权限（Linux）
        String os = System.getProperty("os.name").toLowerCase();

        if (os.contains("win")) {
            // Windows: 检查是否以管理员运行
            try {
                Process process = Runtime.getRuntime().exec("net session");
                process.waitFor();
                return process.exitValue() == 0;
            } catch (Exception e) {
                log.warn("无法检查管理员权限: {}", e.getMessage());
                return false;
            }
        } else if (os.contains("linux")) {
            // Linux: 检查是否为 root
            return "root".equals(System.getProperty("user.name"));
        }

        return false;
    }
}