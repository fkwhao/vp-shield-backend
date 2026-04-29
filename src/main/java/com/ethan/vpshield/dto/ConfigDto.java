package com.ethan.vpshield.dto;

import lombok.Data;

/**
 * 配置信息 DTO
 * 用于 API 返回，避免直接序列化 Spring 代理对象
 */
@Data
public class ConfigDto {

    private CaptureConfig capture;
    private DefenseConfig defense;
    private AttackConfig attack;

    @Data
    public static class CaptureConfig {
        private String interfaceName;
        private boolean promiscuous;
        private int bufferSize;
        private int readTimeout;
    }

    @Data
    public static class DefenseConfig {
        private int icmpReplyThreshold;
        private int tcpSynThreshold;
        private int udpThreshold;
        private long statsWindowMs;
        private long alertCooldownMs;
        private boolean autoBlock;
        private int blockDurationMinutes;
        private boolean rateLimit;
        private int rateLimitRecoverySeconds;
        private int autoBlockWindowSeconds;
        private int autoBlockAttackThreshold;
        private boolean repeatAttackBlock;
        private boolean emergencyDefense;
        private int emergencySourceIpThreshold;
        private int emergencyPpsThreshold;
        private boolean emergencyStopCapture;
        private int emergencyRecoverySeconds;
    }

    @Data
    public static class AttackConfig {
        private int defaultPacketCount;
        private long packetIntervalMs;
    }
}
