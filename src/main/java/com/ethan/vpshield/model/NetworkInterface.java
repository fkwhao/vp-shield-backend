package com.ethan.vpshield.model;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * 网络接口信息模型
 * 用于展示可用的抓包网卡
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class NetworkInterface {

    /** 网卡名称 */
    private String name;

    /** 网卡描述 */
    private String description;

    /** 网卡 MAC 地址 */
    private String macAddress;

    /** 是否支持混杂模式 */
    private boolean promiscuousSupported;

    /** 是否已连接 */
    private boolean isUp;

    /** IP 地址列表 */
    private java.util.List<String> ipAddresses;

    /** 是否为回环接口 */
    private boolean isLoopback;
}