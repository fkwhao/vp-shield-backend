package com.ethan.vpshield.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 系统状态响应 DTO
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SystemStatus {

    /** 是否正在抓包 */
    private boolean capturing;

    /** 是否正在攻击 */
    private boolean attacking;

    /** 已发送攻击包数量 */
    private long packetsSent;

    /** 当前检测到的攻击源数量 */
    private int attackSourceCount;

    /** 当前 ICMP Reply 阈值 */
    private int icmpThreshold;
}