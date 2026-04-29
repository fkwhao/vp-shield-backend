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

    private volatile String currentFilter = "ip";

    @Getter
    private volatile boolean emergencyMode = false;

    /**
     * 获取可用网络接口列表
     *
     * @return 网络接口列表
     */
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

    /**
     * 启动抓包
     *
     * @param interfaceName 网卡名称，为空则自动选择
     * @param handler 数据包处理器
     * @param errorHandler 错误处理器
     */
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

    /**
     * 停止抓包
     */
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

    /**
     * 抓包循环
     */
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

    /**
     * 解析数据包，提取协议信息
     *
     * @param packet 原始数据包
     * @return 解析后的数据包信息，解析失败返回 null
     */
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

    /**
     * 格式化 MAC 地址
     *
     * @param addresses 链路层地址列表
     * @return 格式化后的 MAC 地址字符串
     */
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

    /**
     * 提取网卡的 IPv4 地址列表
     *
     * @param dev 网络接口
     * @return IPv4 地址列表
     */
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

    /**
     * 关闭抓包句柄
     */
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

    /**
     * 服务销毁时停止抓包
     */
    @PreDestroy
    public void destroy() throws NotOpenException {
        stopCapture();
    }

    /**
     * 检查是否正在抓包
     *
     * @return true 如果正在抓包
     */
    public boolean isCapturing() {
        return capturing.get();
    }

    // ==================== 紧急防御功能 ====================

    /**
     * 进入紧急防御模式
     * 可以停止抓包或切换到过滤模式
     *
     * @param mode 模式: "stop" 停止抓包, "tcp-only" 只保留TCP, "drop-syn" 过滤SYN包
     * @return true 成功进入紧急模式，false 失败
     */
    public synchronized boolean enterEmergencyMode(String mode) {
        log.info("尝试进入紧急防御模式: {}, 抓包状态: {}", mode, capturing.get());

        if (!capturing.get()) {
            // 即使抓包未运行，也标记为紧急模式
            emergencyMode = true;
            log.warn("抓包未运行，但已标记紧急防御模式");
            return true;
        }

        emergencyMode = true;
        log.warn("!!! 进入紧急防御模式: {} !!!", mode);

        switch (mode) {
            case "stop" -> {
                try {
                    stopCapture();
                    log.warn("抓包已停止，系统不再接收流量");
                } catch (NotOpenException e) {
                    log.error("停止抓包失败", e);
                    return false;
                }
            }
            case "tcp-only" -> {
                // 只保留 TCP 流量，过滤掉 UDP 和 ICMP
                updateFilter("tcp");
                log.warn("过滤器已切换为: 只接收TCP流量");
            }
            case "drop-syn" -> {
                // 过滤掉 TCP SYN 包
                updateFilter("ip and not (tcp and tcp[tcpflags] & tcp-syn != 0)");
                log.warn("过滤器已切换为: 过滤TCP SYN包");
            }
            case "drop-udp" -> {
                updateFilter("ip and not udp");
                log.warn("过滤器已切换为: 过滤UDP流量");
            }
            case "drop-icmp" -> {
                updateFilter("ip and not icmp");
                log.warn("过滤器已切换为: 过滤ICMP流量");
            }
            case "established-only" -> {
                // 只保留已建立的TCP连接（非SYN包）
                updateFilter("tcp and tcp[tcpflags] & tcp-syn == 0");
                log.warn("过滤器已切换为: 只接收已建立的TCP连接");
            }
            default -> {
                log.warn("未知的紧急模式: {}, 使用默认模式", mode);
                updateFilter("tcp and tcp[tcpflags] & tcp-syn == 0");
            }
        }
        return true;
    }

    /**
     * 退出紧急防御模式，恢复正常抓包
     */
    public synchronized void exitEmergencyMode() {
        if (!emergencyMode) {
            return;
        }

        emergencyMode = false;
        log.info("退出紧急防御模式，恢复正常抓包");

        // 恢复默认过滤器
        if (capturing.get()) {
            updateFilter("ip");
        }
    }

    /**
     * 动态更新 BPF 过滤器
     */
    private void updateFilter(String filter) {
        if (pcapHandle == null || !pcapHandle.isOpen()) {
            log.warn("抓包句柄未打开，无法更新过滤器");
            return;
        }

        try {
            currentFilter = filter;
            // 使用 null netmask 时，pcap4j 会自动处理
            // 对于某些复杂过滤器，需要指定 netmask
            Inet4Address netmask = getNetmaskForFilter();
            BpfProgram bpfFilter = pcapHandle.compileFilter(filter, BpfCompileMode.OPTIMIZE, netmask);
            pcapHandle.setFilter(bpfFilter);
            log.info("BPF过滤器已更新: {}", filter);
        } catch (PcapNativeException | NotOpenException e) {
            log.error("更新过滤器失败: {} - {}", filter, e.getMessage());
            // 尝试使用简化过滤器
            tryFallbackFilter(filter);
        }
    }

    /**
     * 获取用于过滤器的 netmask
     */
    private Inet4Address getNetmaskForFilter() {
        try {
            // 尝试获取当前网卡的 netmask
            if (pcapHandle != null) {
                // 默认使用 255.255.255.0
                return (Inet4Address) InetAddress.getByName("255.255.255.0");
            }
        } catch (Exception e) {
            log.debug("无法获取 netmask: {}", e.getMessage());
        }
        return null;
    }

    /**
     * 过滤器失败时的备用方案
     */
    private void tryFallbackFilter(String originalFilter) {
        String fallbackFilter = "ip";
        try {
            log.warn("尝试使用备用过滤器: {}", fallbackFilter);
            BpfProgram bpfFilter = pcapHandle.compileFilter(fallbackFilter, BpfCompileMode.OPTIMIZE, null);
            pcapHandle.setFilter(bpfFilter);
            currentFilter = fallbackFilter;
            log.info("备用过滤器已应用");
        } catch (Exception e) {
            log.error("备用过滤器也失败: {}", e.getMessage());
        }
    }

    /**
     * 获取当前过滤器
     */
    public String getCurrentFilter() {
        return currentFilter;
    }
}