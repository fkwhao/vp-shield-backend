package com.ethan.vpshield.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

/**
 * 安全告警模型
 * 记录检测到的攻击事件
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Alert {

    /** 告警 ID */
    private String alertId;

    /** 告警时间 */
    private LocalDateTime timestamp;

    /** 告警级别 */
    private Severity severity;

    /** 告警类型 */
    private AlertType alertType;

    /** 告警标题 */
    private String title;

    /** 告警详情 */
    private String description;

    /** 攻击源 IP */
    private String sourceIp;

    /** 所有攻击源 IP 列表 */
    private List<String> sourceIps;

    /** 受害者 IP */
    private String targetIp;

    /** 相关统计信息 */
    private TrafficStats relatedStats;

    /**
     * 告警级别枚举
     */
    public enum Severity {
        INFO,
        WARNING,
        CRITICAL
    }

    /**
     * 告警类型枚举
     */
    public enum AlertType {
        SMURF_ATTACK,
        SYN_FLOOD,
        ICMP_FLOOD,
        UDP_FLOOD,
        TRAFFIC_ANOMALY,
        PACKET_CAPTURE_ERROR
    }

    /**
     * 创建 Smurf 攻击告警
     */
    public static Alert createSmurfAlert(String sourceIp, String targetIp, TrafficStats stats) {
        return Alert.builder()
                .alertId(java.util.UUID.randomUUID().toString())
                .timestamp(LocalDateTime.now())
                .severity(Severity.CRITICAL)
                .alertType(AlertType.SMURF_ATTACK)
                .title("检测到 Smurf 攻击")
                .description(String.format(
                        "检测到异常 ICMP Echo Reply 流量激增，疑似 Smurf 攻击。" +
                        "ICMP Reply 数量: %d 包/秒，攻击源: %s。",
                        stats.getIcmpReplyCount(), sourceIp))
                .sourceIp(sourceIp)
                .sourceIps(List.of(sourceIp))
                .targetIp(targetIp)
                .relatedStats(stats)
                .build();
    }
}