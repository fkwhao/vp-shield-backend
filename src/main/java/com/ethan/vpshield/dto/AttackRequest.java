package com.ethan.vpshield.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

/**
 * 攻击参数请求 DTO
 */
@Data
public class AttackRequest {

    /** 受害者 IP 地址 */
    @NotBlank(message = "受害者 IP 不能为空")
    private String victimIp;

    /** 广播地址 */
    @NotBlank(message = "广播地址不能为空")
    private String broadcastIp;

    /** 发送包数量 */
    @Min(value = 1, message = "包数量至少为 1")
    @Max(value = 10000, message = "包数量不能超过 10000")
    private int packetCount = 100;

    /** 网卡名称（可选） */
    private String interfaceName;
}