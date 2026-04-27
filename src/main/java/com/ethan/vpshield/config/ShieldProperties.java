package com.ethan.vpshield.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * 网络安全监控配置属性
 * 从 application.yml 加载配置参数
 */
@Data
@Configuration
@ConfigurationProperties(prefix = "vpshield")
public class ShieldProperties {

    /**
     * 抓包配置
     */
    private CaptureConfig capture = new CaptureConfig();

    /**
     * 防御检测配置
     */
    private DefenseConfig defense = new DefenseConfig();

    /**
     * 攻击模拟配置
     */
    private AttackConfig attack = new AttackConfig();

    @Data
    public static class CaptureConfig {
        /** 网卡名称，为空则自动选择 */
        private String interfaceName;

        /** 混杂模式开关 */
        private boolean promiscuous = true;

        /** 抓包缓冲区大小（字节） */
        private int bufferSize = 65536;

        /** 读取超时时间（毫秒） */
        private int readTimeout = 100;
    }

    @Data
    public static class DefenseConfig {
        /** ICMP Echo Reply 阈值（包/秒） */
        private int icmpReplyThreshold = 100;

        /** TCP SYN 包阈值（包/秒） */
        private int tcpSynThreshold = 1000;

        /** UDP 包阈值（包/秒） */
        private int udpThreshold = 5000;

        /** 统计时间窗口（毫秒） */
        private long statsWindowMs = 1000;

        /** 告警冷却时间（毫秒），防止告警风暴 */
        private long alertCooldownMs = 5000;

        /** 自动封禁开关 */
        private boolean autoBlock = false;

        /** 封禁时长（分钟），0 表示永久 */
        private int blockDurationMinutes = 60;

        /** 流量限速开关（推荐用于伪造 IP 攻击） */
        private boolean rateLimit = true;

        /** 限速恢复时间（秒），攻击停止后自动恢复 */
        private int rateLimitRecoverySeconds = 60;

        /** IP 自动封禁：时间窗口（秒），统计该时间内的攻击次数 */
        private int autoBlockWindowSeconds = 30;

        /** IP 自动封禁：窗口内攻击次数阈值，超过则自动封禁 */
        private int autoBlockAttackThreshold = 3;

        /** IP 自动封禁开关（基于重复攻击检测） */
        private boolean repeatAttackBlock = true;

        // ==================== 紧急防御配置 ====================

        /** 紧急防御模式开关 */
        private boolean emergencyDefense = true;

        /** 触发紧急防御的唯一源IP阈值（大量不同IP攻击） */
        private int emergencySourceIpThreshold = 5;

        /** 触发紧急防御的PPS阈值 */
        private int emergencyPpsThreshold = 50000;

        /** 紧急防御时是否停止抓包（彻底停止接收） */
        private boolean emergencyStopCapture = false;

        /** 紧急防御自动恢复时间（秒），0表示不自动恢复 */
        private int emergencyRecoverySeconds = 120;
    }

    @Data
    public static class AttackConfig {
        /** 默认攻击包数量 */
        private int defaultPacketCount = 100;

        /** 攻击包发送间隔（毫秒） */
        private long packetIntervalMs = 10;
    }
}