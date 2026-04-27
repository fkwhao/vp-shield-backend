package com.ethan.vpshield.service.defense;

import com.ethan.vpshield.config.ShieldProperties;
import com.ethan.vpshield.model.Alert;
import com.ethan.vpshield.model.TrafficStats;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.List;

/**
 * 流量限速防御策略
 *
 * Windows 防御措施：
 * 1. 阻止攻击源 IP
 * 2. 启用系统 SYN 攻击保护
 * 3. 配置注册表参数
 *
 * Linux 防御措施：
 * 1. iptables 阻止攻击源
 * 2. tc 流量控制
 * 3. sysctl 内核参数调优
 */
@Slf4j
@Component
@RequiredArgsConstructor
public class RateLimitStrategy implements DefenseStrategy {

    private static final String WIN_SYN_RULE = "VP-Shield-SYN-Defense";
    private static final String WIN_ICMP_RULE = "VP-Shield-ICMP-Defense";
    private static final String WIN_BLOCK_PREFIX = "VP-Shield-Block-";

    private final ShieldProperties properties;
    private volatile boolean rateLimitEnabled = false;

    @Override
    public String getName() {
        return "Rate Limit";
    }

    @Override
    public Alert.AlertType getSupportedAttackType() {
        return null;
    }

    @Override
    public DefenseResult execute(Alert alert, TrafficStats stats) {
        log.warn("Applying defense for attack type: {}", alert.getAlertType());

        if (!canExecute()) {
            String msg = "需要管理员权限才能执行防御措施！请以管理员身份运行程序。";
            log.error(msg);
            return DefenseResult.failure(msg);
        }

        try {
            clearRateLimitRules();

            // 1. 阻止攻击源 IP（所有配置文件）
            int blockedCount = blockAttackSources(alert);

            // 2. 根据攻击类型启用额外防护
            switch (alert.getAlertType()) {
                case SYN_FLOOD -> {
                    enableSynFloodDefense();
                    enableRegistrySynProtection();
                    // 激进措施：临时关闭 TCP 连接接受
                    enableAggressiveSynDefense();
                }
                case SMURF_ATTACK, ICMP_FLOOD -> enableIcmpDefense();
                default -> {}
            }

            rateLimitEnabled = true;
            String message = String.format("防御已启用 - 已阻止 %d 个攻击源 IP + 系统级防护", blockedCount);
            log.info(message);
            return DefenseResult.success("DEFENSE_ENABLED", message, alert.getAlertType().name());

        } catch (Exception e) {
            log.error("Defense execution failed", e);
            return DefenseResult.failure("防御执行失败: " + e.getMessage());
        }
    }

    /**
     * 阻止攻击源 IP
     */
    private int blockAttackSources(Alert alert) throws IOException, InterruptedException {
        List<String> sourceIps = alert.getSourceIps();
        int blockedCount = 0;

        if (sourceIps != null && !sourceIps.isEmpty()) {
            for (String ip : sourceIps) {
                if (blockIp(ip)) {
                    blockedCount++;
                }
            }
        } else if (alert.getSourceIp() != null && !"unknown".equals(alert.getSourceIp())) {
            if (blockIp(alert.getSourceIp())) {
                blockedCount = 1;
            }
        }

        return blockedCount;
    }

    /**
     * 阻止单个 IP
     * 注意：必须指定 profile=any 才能应用到所有网络配置文件
     */
    private boolean blockIp(String ip) throws IOException, InterruptedException {
        String os = System.getProperty("os.name").toLowerCase();
        String ruleName = WIN_BLOCK_PREFIX + ip.replace(".", "_");

        if (os.contains("win")) {
            log.info("Blocking IP: {} (including local subnet)", ip);

            // Windows: 使用 netsh 添加阻止规则
            // 关键：profile=any 确保规则应用到所有网络配置文件（域、专用、公用）
            // 这样即使在局域网内也能生效
            String[] commands = {
                    "netsh advfirewall firewall delete rule name=\"" + ruleName + "\"",
                    String.format(
                            "netsh advfirewall firewall add rule name=\"%s\" " +
                            "dir=in action=block remoteip=%s profile=any " +
                            "description=\"VP-Shield: Blocked attack source\"",
                            ruleName, ip),
                    // 同时阻止出站流量
                    String.format(
                            "netsh advfirewall firewall add rule name=\"%s-out\" " +
                            "dir=out action=block remoteip=%s profile=any " +
                            "description=\"VP-Shield: Blocked attack source (outbound)\"",
                            ruleName, ip)
            };

            for (String cmd : commands) {
                Process p = Runtime.getRuntime().exec(cmd);
                p.waitFor();
                if (p.exitValue() != 0) {
                    log.warn("Command failed: {}", cmd);
                }
            }

            log.info("Successfully blocked IP: {} (applied to all profiles)", ip);
            return true;

        } else if (os.contains("linux")) {
            Runtime.getRuntime().exec("sudo iptables -I INPUT -s " + ip + " -j DROP");
            Runtime.getRuntime().exec("sudo iptables -I OUTPUT -d " + ip + " -j DROP");
            log.info("Linux: Blocked IP {} via iptables", ip);
            return true;
        }

        return false;
    }

    /**
     * SYN Flood 防御 - 系统级配置
     */
    private void enableSynFloodDefense() throws IOException, InterruptedException {
        String os = System.getProperty("os.name").toLowerCase();

        if (os.contains("win")) {
            log.info("Enabling Windows SYN Flood protection...");

            // 启用 SYN 攻击保护
            execCommand("netsh int tcp set global synattackprotection=enabled");

            // 启用 TCP 连接限制
            execCommand("netsh int tcp set global maxsynretransmissions=2");

            // 减少动态端口范围，降低攻击面
            execCommand("netsh int ipv4 set dynamicport tcp start=10000 num=1000");

            log.info("Windows SYN Flood protection enabled");
        }
    }

    /**
     * 激进的 SYN 防御措施
     * 当攻击严重时，临时启用更严格的限制
     */
    private void enableAggressiveSynDefense() {
        String os = System.getProperty("os.name").toLowerCase();
        if (!os.contains("win")) return;

        log.warn("Enabling AGGRESSIVE SYN defense mode...");

        try {
            // 更严格的半开连接限制
            execRegAdd("HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                    "TcpMaxHalfOpen", "100");

            execRegAdd("HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                    "TcpMaxHalfOpenRetried", "80");

            // 更低的触发阈值
            execRegAdd("HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                    "TcpMaxPortsExhausted", "1");

            // 更快的超时
            execRegAdd("HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                    "TcpTimedWaitDelay", "10");

            log.warn("Aggressive SYN defense enabled - stricter limits applied");
            log.info("NOTE: These registry changes may require system restart to fully take effect");

        } catch (Exception e) {
            log.warn("Failed to enable aggressive defense: {}", e.getMessage());
        }
    }

    /**
     * 通过注册表启用 SYN 攻击保护（更彻底）
     */
    private void enableRegistrySynProtection() {
        String os = System.getProperty("os.name").toLowerCase();
        if (!os.contains("win")) return;

        log.info("Configuring registry for SYN attack protection...");

        try {
            // SynAttackProtect = 2 (最高级别保护)
            // 0 = 禁用
            // 1 = 减少 SYN-ACK 重传次数，延迟路由缓存
            // 2 = 在 1 的基础上，对 Winsock 连接进行更严格的限制
            execRegAdd("HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                    "SynAttackProtect", "2");

            // TcpMaxHalfOpen: 半开连接的最大数量
            // 当超过此值时，系统开始丢弃新的 SYN 请求
            execRegAdd("HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                    "TcpMaxHalfOpen", "500");

            // TcpMaxHalfOpenRetried: 已重传的半开连接最大数量
            execRegAdd("HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                    "TcpMaxHalfOpenRetried", "400");

            // TcpMaxPortsExhausted: 触发 SYN 攻击保护的阈值
            // 当系统在 TcpMaxHalfOpenRetried 限制内拒绝了这么多连接请求后，
            // SYN 攻击保护就会启动
            execRegAdd("HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                    "TcpMaxPortsExhausted", "5");

            // 减少连接超时时间（秒）
            execRegAdd("HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters",
                    "TcpTimedWaitDelay", "30");

            log.info("Registry SYN protection configured. Some settings require restart.");

        } catch (Exception e) {
            log.warn("Failed to configure registry: {}", e.getMessage());
        }
    }

    /**
     * ICMP 防御
     */
    private void enableIcmpDefense() throws IOException, InterruptedException {
        String os = System.getProperty("os.name").toLowerCase();

        if (os.contains("win")) {
            log.info("Enabling ICMP Flood protection...");

            // 删除旧规则
            Runtime.getRuntime().exec("netsh advfirewall firewall delete rule name=\"" + WIN_ICMP_RULE + "\"").waitFor();

            // 阻止入站 ICMP（应用到所有配置文件）
            String cmd = String.format(
                    "netsh advfirewall firewall add rule name=\"%s\" " +
                    "dir=in action=block protocol=icmpv4 profile=any " +
                    "description=\"VP-Shield: Block ICMP flood\"",
                    WIN_ICMP_RULE);
            Runtime.getRuntime().exec(cmd).waitFor();

            log.info("ICMP Flood protection enabled (all profiles)");
        }
    }

    private void execCommand(String command) throws IOException, InterruptedException {
        Process p = Runtime.getRuntime().exec(command);
        p.waitFor();
        if (p.exitValue() != 0) {
            log.warn("Command failed: {} (exit code: {})", command, p.exitValue());
        }
    }

    private void execRegAdd(String key, String valueName, String value) throws IOException, InterruptedException {
        String cmd = String.format("reg add \"%s\" /v %s /t REG_DWORD /d %s /f", key, valueName, value);
        Process p = Runtime.getRuntime().exec(cmd);
        p.waitFor();
        if (p.exitValue() == 0) {
            log.info("Registry set: {} = {}", valueName, value);
        } else {
            log.warn("Failed to set registry: {}", valueName);
        }
    }

    public void disableRateLimit() {
        try {
            clearRateLimitRules();
        } catch (IOException e) {
            log.error("Failed to cleanup rules", e);
        } finally {
            rateLimitEnabled = false;
        }
    }

    private void clearRateLimitRules() throws IOException {
        String os = System.getProperty("os.name").toLowerCase();

        if (os.contains("win")) {
            try {
                // 删除 SYN 和 ICMP 规则
                Runtime.getRuntime().exec("netsh advfirewall firewall delete rule name=\"" + WIN_SYN_RULE + "\"").waitFor();
                Runtime.getRuntime().exec("netsh advfirewall firewall delete rule name=\"" + WIN_ICMP_RULE + "\"").waitFor();

                // 删除所有 VP-Shield-Block-* 规则（包括入站和出站）
                String psCmd = "Get-NetFirewallRule -DisplayName 'VP-Shield-Block-*' | Remove-NetFirewallRule -ErrorAction SilentlyContinue; " +
                               "Get-NetFirewallRule -DisplayName 'VP-Shield-Block-*-out' | Remove-NetFirewallRule -ErrorAction SilentlyContinue";
                Runtime.getRuntime().exec(new String[]{"powershell", "-Command", psCmd}).waitFor();

                log.info("Firewall rules cleanup completed");
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
        }
    }

    public boolean isRateLimitEnabled() {
        return rateLimitEnabled;
    }

    @Override
    public boolean canExecute() {
        String os = System.getProperty("os.name").toLowerCase();
        if (os.contains("win")) {
            try {
                Process process = Runtime.getRuntime().exec("net session");
                process.waitFor();
                return process.exitValue() == 0;
            } catch (Exception e) {
                return false;
            }
        } else if (os.contains("linux")) {
            return "root".equals(System.getProperty("user.name"));
        }
        return false;
    }
}
