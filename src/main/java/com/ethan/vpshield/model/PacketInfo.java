package com.ethan.vpshield.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * 数据包信息模型
 * 封装从 Pcap4j 解析的网络包元数据
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PacketInfo {

    /** 时间戳 */
    private LocalDateTime timestamp;

    /** 源 IP 地址 */
    private String sourceIp;

    /** 目的 IP 地址 */
    private String destinationIp;

    /** 协议类型 (ICMP, TCP, UDP 等) */
    private Protocol protocol;

    /** 数据包大小（字节） */
    private int packetSize;

    /** ICMP 类型（仅 ICMP 包有效） */
    private Integer icmpType;

    /** ICMP 代码（仅 ICMP 包有效） */
    private Integer icmpCode;

    /** 源端口（TCP/UDP） */
    private Integer sourcePort;

    /** 目的端口（TCP/UDP） */
    private Integer destinationPort;

    /** TCP 标志位（仅 TCP 包有效） */
    private TcpFlags tcpFlags;

    /** 原始数据（十六进制字符串，可选） */
    private String rawData;

    /**
     * TCP 标志位
     */
    @Data
    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    public static class TcpFlags {
        private boolean syn;
        private boolean ack;
        private boolean fin;
        private boolean rst;
        private boolean psh;
        private boolean urg;
    }

    /**
     * 网络协议枚举
     */
    public enum Protocol {
        ICMP,
        TCP,
        UDP,
        ARP,
        IPv4,
        IPv6,
        UNKNOWN
    }

    /**
     * ICMP 类型常量
     */
    public static final int ICMP_ECHO_REQUEST = 8;
    public static final int ICMP_ECHO_REPLY = 0;
}