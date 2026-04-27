package com.ethan.vpshield.service;

import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.Pcaps;

import java.util.List;

/**
 * 网络接口工具类
 */
final class NetworkInterfaceUtil {

    private NetworkInterfaceUtil() {
    }

    /**
     * 选择网络接口
     *
     * @param interfaceName 网卡名称，为空则自动选择
     * @return 网络接口
     */
    static PcapNetworkInterface selectInterface(String interfaceName) throws PcapNativeException {
        if (interfaceName != null && !interfaceName.isEmpty()) {
            return Pcaps.getDevByName(interfaceName);
        }

        List<PcapNetworkInterface> devs = Pcaps.findAllDevs();
        for (PcapNetworkInterface dev : devs) {
            if (!dev.isLoopBack() && dev.isUp()) {
                return dev;
            }
        }
        return devs.isEmpty() ? null : devs.get(0);
    }
}