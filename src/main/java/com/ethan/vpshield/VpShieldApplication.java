package com.ethan.vpshield;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * VP-Shield 网络安全监控系统
 *
 * 功能：
 * 1. 流量捕获 - 使用 Pcap4j 监听指定网卡
 * 2. 攻击模拟 - Smurf 攻击逻辑实现
 * 3. 防御检测 - 基于特征匹配的攻击检测
 * 4. 实时通信 - WebSocket 推送流量数据和告警
 *
 * @author Ethan
 */
@SpringBootApplication
@EnableScheduling
public class VpShieldApplication {

    public static void main(String[] args) {
        SpringApplication.run(VpShieldApplication.class, args);
    }
}