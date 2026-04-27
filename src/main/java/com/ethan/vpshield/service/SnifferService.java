package com.ethan.vpshield.service;

import com.ethan.vpshield.config.ShieldProperties;
import com.ethan.vpshield.model.NetworkInterface;
import com.ethan.vpshield.model.PacketInfo;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.*;
import org.pcap4j.core.BpfProgram.BpfCompileMode;
import org.pcap4j.core.PcapNetworkInterface.PromiscuousMode;
import org.pcap4j.packet.*;
import org.pcap4j.util.LinkLayerAddress;
import org.springframework.stereotype.Service;

import jakarta.annotation.PreDestroy;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;

/**
 * 流量捕获服务
 * 使用 Pcap4j 实现底层网络包捕获和协议解析
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SnifferService {

    private final ShieldProperties properties;

    @Getter
    private PcapHandle pcapHandle;

    private Thread captureThread;

    private final AtomicBoolean capturing = new AtomicBoolean(false);

    private Consumer<PacketInfo> packetHandler;

    private Consumer<Exception> errorHandler;

    public List<NetworkInterface> getAvailableInterfaces() {
        List<NetworkInterface> interfaces = new ArrayList<>();

        try {
            List<PcapNetworkInterface> devs = Pcaps.findAllDevs();

            for (PcapNetworkInterface dev : devs) {
                NetworkInterface ni = NetworkInterface.builder()
                        .name(dev.getName())
                        .description(dev.getDescription())
                        .macAddress(formatMacAddress(dev.getLinkLayerAddresses()))
                        .promiscuousSupported(true)
                        .isUp(dev.isUp())
                        .ipAddresses(extractIpAddresses(dev))
                        .isLoopback(dev.isLoopBack())
                        .build();
                interfaces.add(ni);
            }
        } catch (PcapNativeException e) {
            log.error("获取网络接口列表失败", e);
        }

        return interfaces;
    }

    public synchronized void startCapture(String interfaceName,
                                           Consumer<PacketInfo> handler,
                                           Consumer<Exception> errorHandler) {
        if (capturing.get()) {
            log.warn("抓包已在运行中");
            return;
        }

        this.packetHandler = handler;
        this.errorHandler = errorHandler;

        try {
            PcapNetworkInterface nif = NetworkInterfaceUtil.selectInterface(interfaceName);
            if (nif == null) {
                throw new PcapNativeException("未找到可用的网络接口");
            }

            log.info("选择网卡: {} - {}", nif.getName(), nif.getDescription());

            int snapLen = properties.getCapture().getBufferSize();
            PromiscuousMode mode = properties.getCapture().isPromiscuous()
                    ? PromiscuousMode.PROMISCUOUS
                    : PromiscuousMode.NONPROMISCUOUS;
            int timeout = properties.getCapture().getReadTimeout();

            pcapHandle = nif.openLive(snapLen, mode, timeout);

            // 获取网卡的 netmask 用于编译过滤器
            Inet4Address netmask = getNetmask(nif);
            BpfProgram filter = pcapHandle.compileFilter("ip", BpfCompileMode.OPTIMIZE, netmask);
            pcapHandle.setFilter(filter);

            capturing.set(true);

            captureThread = new Thread(this::captureLoop, "packet-capture");
            captureThread.setDaemon(true);
            captureThread.start();

            log.info("抓包已启动");

        } catch (PcapNativeException | NotOpenException e) {
            log.error("启动抓包失败", e);
            if (errorHandler != null) {
                errorHandler.accept(e);
            }
        }
    }

    /**
     * 获取网卡的子网掩码
     */
    private Inet4Address getNetmask(PcapNetworkInterface nif) {
        for (PcapAddress addr : nif.getAddresses()) {
            if (addr.getAddress() instanceof Inet4Address && addr.getNetmask() != null) {
                return (Inet4Address) addr.getNetmask();
            }
        }
        // 默认返回 255.255.255.0
        try {
            return (Inet4Address) InetAddress.getByName("255.255.255.0");
        } catch (Exception e) {
            return null;
        }
    }

    public synchronized void stopCapture() throws NotOpenException {
        if (!capturing.get()) {
            return;
        }

        capturing.set(false);

        if (pcapHandle != null && pcapHandle.isOpen()) {
            pcapHandle.breakLoop();
        }

        if (captureThread != null) {
            try {
                captureThread.join(1000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }

        closeHandle();
        log.info("抓包已停止");
    }

    private void captureLoop() {
        try {
            PacketListener listener = packet -> {
                if (!capturing.get() || packetHandler == null) {
                    return;
                }
                try {
                    PacketInfo info = parsePacket(packet);
                    if (info != null) {
                        packetHandler.accept(info);
                    }
                } catch (Exception e) {
                    log.debug("解析数据包失败: {}", e.getMessage());
                }
            };

            pcapHandle.loop(-1, listener);
        } catch (PcapNativeException | NotOpenException | InterruptedException e) {
            if (capturing.get() && errorHandler != null) {
                errorHandler.accept(e);
            }
        }
    }

    private PacketInfo parsePacket(Packet packet) {
        PacketInfo.PacketInfoBuilder builder = PacketInfo.builder()
                .timestamp(LocalDateTime.now())
                .packetSize(packet.length());

        EthernetPacket ethernet = packet.get(EthernetPacket.class);
        if (ethernet == null) {
            return null;
        }

        IpPacket ipPacket = packet.get(IpPacket.class);
        if (ipPacket == null) {
            return null;
        }

        builder.sourceIp(ipPacket.getHeader().getSrcAddr().getHostAddress())
                .destinationIp(ipPacket.getHeader().getDstAddr().getHostAddress());

        IcmpV4CommonPacket icmpPacket = packet.get(IcmpV4CommonPacket.class);
        if (icmpPacket != null) {
            builder.protocol(PacketInfo.Protocol.ICMP);
            byte icmpTypeValue = icmpPacket.getHeader().getType().value();
            byte icmpCodeValue = icmpPacket.getHeader().getCode().value();
            builder.icmpType((int) icmpTypeValue).icmpCode((int) icmpCodeValue);
            return builder.build();
        }

        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null) {
            builder.protocol(PacketInfo.Protocol.TCP);

            // 解析端口
            builder.sourcePort((int) tcpPacket.getHeader().getSrcPort().value());
            builder.destinationPort((int) tcpPacket.getHeader().getDstPort().value());

            // 解析 TCP 标志位
            TcpPacket.TcpHeader tcpHeader = tcpPacket.getHeader();
            PacketInfo.TcpFlags flags = PacketInfo.TcpFlags.builder()
                    .syn(tcpHeader.getSyn())
                    .ack(tcpHeader.getAck())
                    .fin(tcpHeader.getFin())
                    .rst(tcpHeader.getRst())
                    .psh(tcpHeader.getPsh())
                    .urg(tcpHeader.getUrg())
                    .build();
            builder.tcpFlags(flags);

            return builder.build();
        }

        UdpPacket udpPacket = packet.get(UdpPacket.class);
        if (udpPacket != null) {
            builder.protocol(PacketInfo.Protocol.UDP);
            return builder.build();
        }

        builder.protocol(PacketInfo.Protocol.UNKNOWN);
        return builder.build();
    }

    private String formatMacAddress(List<LinkLayerAddress> addresses) {
        if (addresses == null || addresses.isEmpty()) {
            return null;
        }
        byte[] mac = addresses.get(0).getAddress();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < mac.length; i++) {
            if (i > 0) sb.append(":");
            sb.append(String.format("%02X", mac[i] & 0xFF));
        }
        return sb.toString();
    }

    private List<String> extractIpAddresses(PcapNetworkInterface dev) {
        List<String> ips = new ArrayList<>();
        for (PcapAddress addr : dev.getAddresses()) {
            InetAddress inetAddr = addr.getAddress();
            if (inetAddr instanceof Inet4Address) {
                ips.add(inetAddr.getHostAddress());
            }
        }
        return ips;
    }

    private void closeHandle() {
        if (pcapHandle != null) {
            try {
                if (pcapHandle.isOpen()) {
                    pcapHandle.close();
                }
            } catch (Exception e) {
                log.warn("关闭抓包句柄失败", e);
            }
            pcapHandle = null;
        }
    }

    @PreDestroy
    public void destroy() throws NotOpenException {
        stopCapture();
    }

    public boolean isCapturing() {
        return capturing.get();
    }
}