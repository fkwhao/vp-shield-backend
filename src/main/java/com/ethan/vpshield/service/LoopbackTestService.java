package com.ethan.vpshield.service;

import com.ethan.vpshield.model.PacketInfo;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.net.InetAddress;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 本机回环测试服务
 * 用于验证检测逻辑，不修改核心攻击/防御代码
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LoopbackTestService {

    private final DefenseMonitor defenseMonitor;

    private final AtomicBoolean testing = new AtomicBoolean(false);
    private ExecutorService executor;

    /**
     * 启动回环测试
     * 模拟 Smurf 攻击流量，验证检测逻辑
     *
     * @param packetCount 模拟包数量
     * @param sourceIpCount 模拟的源 IP 数量
     */
    public void startTest(int packetCount, int sourceIpCount) {
        if (testing.get()) {
            log.warn("测试已在运行中");
            return;
        }

        testing.set(true);
        executor = Executors.newSingleThreadExecutor();

        executor.submit(() -> {
            try {
                log.info("开始回环测试 - 模拟 {} 个 ICMP Reply 包，来自 {} 个源 IP",
                        packetCount, sourceIpCount);

                Random random = new Random();
                String localIp = InetAddress.getLocalHost().getHostAddress();

                for (int i = 0; i < packetCount && testing.get(); i++) {
                    // 模拟多个源 IP 发送 ICMP Echo Reply
                    String fakeSourceIp = generateFakeIp(random, sourceIpCount, i);

                    PacketInfo packet = PacketInfo.builder()
                            .timestamp(java.time.LocalDateTime.now())
                            .sourceIp(fakeSourceIp)
                            .destinationIp(localIp)
                            .protocol(PacketInfo.Protocol.ICMP)
                            .icmpType(PacketInfo.ICMP_ECHO_REPLY)
                            .icmpCode(0)
                            .packetSize(64)
                            .build();

                    defenseMonitor.processPacket(packet);

                    // 控制发送速率（每 5ms 发一个包，200 个包约 1 秒）
                    TimeUnit.MILLISECONDS.sleep(5);
                }

                log.info("回环测试完成");

            } catch (Exception e) {
                log.error("回环测试失败", e);
            } finally {
                testing.set(false);
            }
        });
    }

    /**
     * 停止测试
     */
    public void stopTest() {
        testing.set(false);
        if (executor != null) {
            executor.shutdownNow();
        }
        log.info("回环测试已停止");
    }

    public boolean isTesting() {
        return testing.get();
    }

    /**
     * 生成模拟的源 IP 地址
     */
    private String generateFakeIp(Random random, int sourceIpCount, int index) {
        // 使用固定的几个 IP 模拟多个攻击源
        int ipSuffix = 100 + (index % sourceIpCount);
        return "192.168.1." + ipSuffix;
    }
}
