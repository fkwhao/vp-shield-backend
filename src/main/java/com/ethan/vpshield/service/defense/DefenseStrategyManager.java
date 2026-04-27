package com.ethan.vpshield.service.defense;

import com.ethan.vpshield.model.Alert;
import com.ethan.vpshield.model.TrafficStats;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * 防御策略管理器
 * 根据攻击类型选择并执行对应的防御策略
 */
@Slf4j
@Component
public class DefenseStrategyManager {

    private final Map<Alert.AlertType, DefenseStrategy> strategyMap = new HashMap<>();

    /**
     * 自动注入所有 DefenseStrategy 实现
     */
    public DefenseStrategyManager(List<DefenseStrategy> strategies) {
        for (DefenseStrategy strategy : strategies) {
            strategyMap.put(strategy.getSupportedAttackType(), strategy);
            log.info("注册防御策略: {} -> {}", strategy.getSupportedAttackType(), strategy.getName());
        }
    }

    /**
     * 执行防御
     *
     * @param alert 告警信息
     * @param stats 流量统计
     * @return 防御结果
     */
    public DefenseStrategy.DefenseResult executeDefense(Alert alert, TrafficStats stats) {
        Alert.AlertType attackType = alert.getAlertType();
        DefenseStrategy strategy = strategyMap.get(attackType);

        if (strategy == null) {
            log.warn("未找到对应的防御策略: {}", attackType);
            return DefenseStrategy.DefenseResult.failure("未找到对应的防御策略: " + attackType);
        }

        log.info("执行防御策略: {} for {}", strategy.getName(), attackType);
        return strategy.execute(alert, stats);
    }

    /**
     * 获取支持的攻击类型
     */
    public List<Alert.AlertType> getSupportedAttackTypes() {
        return List.copyOf(strategyMap.keySet());
    }

    /**
     * 获取策略信息
     */
    public Map<Alert.AlertType, String> getStrategyInfo() {
        Map<Alert.AlertType, String> info = new HashMap<>();
        strategyMap.forEach((type, strategy) -> info.put(type, strategy.getName()));
        return info;
    }

    /**
     * 检查策略是否可用
     */
    public boolean isStrategyAvailable(Alert.AlertType attackType) {
        DefenseStrategy strategy = strategyMap.get(attackType);
        return strategy != null && strategy.canExecute();
    }
}