package com.ethan.vpshield.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 流量统计模型
 * 用于实时展示网络流量状态
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TrafficStats {

    /** 统计时间戳 */
    private LocalDateTime timestamp;

    /** 总包数（PPS - Packets Per Second） */
    private long totalPackets;

    /** ICMP 包数 */
    private long icmpPackets;

    /** ICMP Echo Reply 包数 */
    private long icmpReplyCount;

    /** TCP SYN 包数（用于 SYN Flood 检测） */
    private long tcpSynCount;

    /** TCP 包数 */
    private long tcpPackets;

    /** UDP 包数 */
    private long udpPackets;

    /** 总字节数 */
    private long totalBytes;

    /** 带宽占用（bps） */
    private double bandwidthBps;

    /** 带宽占用（KB/s） */
    private double bandwidthKBps;

    /** 唯一源 IP 数量 */
    private int uniqueSourceIps;

    /** 唯一目的 IP 数量 */
    private int uniqueDestinationIps;

    /** 是否检测到攻击 */
    private boolean attackDetected;

    /**
     * 创建空统计对象
     */
    public static TrafficStats empty() {
        return TrafficStats.builder()
                .timestamp(LocalDateTime.now())
                .totalPackets(0)
                .icmpPackets(0)
                .icmpReplyCount(0)
                .tcpSynCount(0)
                .tcpPackets(0)
                .udpPackets(0)
                .totalBytes(0)
                .bandwidthBps(0)
                .bandwidthKBps(0)
                .uniqueSourceIps(0)
                .uniqueDestinationIps(0)
                .attackDetected(false)
                .build();
    }
}