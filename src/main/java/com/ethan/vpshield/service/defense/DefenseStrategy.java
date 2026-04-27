package com.ethan.vpshield.service.defense;

import com.ethan.vpshield.model.Alert;
import com.ethan.vpshield.model.TrafficStats;

/**
 * 防御策略接口
 * 不同攻击类型可实现不同的防御逻辑
 */
public interface DefenseStrategy {

    /**
     * 获取策略名称
     */
    String getName();

    /**
     * 获取支持的攻击类型
     */
    Alert.AlertType getSupportedAttackType();

    /**
     * 执行防御动作
     *
     * @param alert 告警信息
     * @param stats 当前流量统计
     * @return 防御结果
     */
    DefenseResult execute(Alert alert, TrafficStats stats);

    /**
     * 检查是否可以执行防御
     * 例如检查权限、系统环境等
     */
    boolean canExecute();

    /**
     * 防御结果
     */
    record DefenseResult(
            boolean success,
            String action,
            String message,
            String[] blockedIps
    ) {
        public static DefenseResult success(String action, String message, String... blockedIps) {
            return new DefenseResult(true, action, message, blockedIps);
        }

        public static DefenseResult failure(String message) {
            return new DefenseResult(false, null, message, null);
        }
    }
}