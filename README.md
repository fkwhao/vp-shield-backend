# VP-Shield

> **网络流量监控与攻击防御系统**

<img src="https://img.shields.io/badge/Spring%20Boot-3.2.5-6DB33F?style=flat-square&logo=springboot" alt="Spring Boot">
<img src="https://img.shields.io/badge/Java-17-ED8B00?style=flat-square&logo=openjdk" alt="Java 17">
<img src="https://img.shields.io/badge/Pcap4j-1.8.2-4479A1?style=flat-square" alt="Pcap4j">
<img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" alt="MIT License">

实时捕获、检测、防御。支持 SYN Flood、UDP Flood、Smurf、ICMP Flood 等多种攻击类型。

---

## 功能概览

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  流量捕获   │ ──► │  攻击检测   │ ──► │  自动防御   │
│  (Pcap4j)   │     │  (多类型)   │     │  (封禁/限速)│
└─────────────┘     └─────────────┘     └─────────────┘
```

### 攻击检测矩阵

| 类型 | 触发条件 | 防御方式 |
|-----|---------|---------|
| **SYN Flood** | TCP SYN > 1000 pps | IP封禁 / SYN限速 |
| **UDP Flood** | UDP > 5000 pps | IP封禁 / UDP限速 |
| **Smurf Attack** | ICMP Reply > 100 pps + 多源IP | IP封禁 |
| **ICMP Flood** | ICMP 异常流量 | IP封禁 / ICMP限速 |
| **Traffic Anomaly** | PPS > 10000 + 少源IP | 流量限速 |

### 防御机制

**IP 封禁** — 真实IP攻击
```
攻击检测 → 提取攻击源IP → 调用防火墙 → 阻断入站流量
Windows: netsh advfirewall
Linux:   iptables
```

**流量限速** — 伪造IP攻击
```
攻击检测 → 启用限速策略 → 按协议限流 → 手动恢复
SYN/UDP/ICMP → 各协议独立限速阈值
```

**自动封禁**
```
时间窗口(30s)内攻击次数 ≥ 3 → 自动封禁IP
防止告警风暴，避免重复处理已封禁IP
```

**紧急防御** — 大规模DDoS攻击（多源IP）
```
检测到多源IP攻击(≥50个) 且 极高PPS → 动态切换BPF过滤器
单一IP攻击优先使用IP封禁，不触发紧急防御
过滤攻击协议，只保留正常流量 → 自动/手动恢复
```

| 模式 | 效果 | 适用场景 |
|-----|-----|---------|
| `established-only` | 只保留已建立TCP连接 | 通用DDoS防护 |
| `drop-udp` | 过滤UDP流量 | UDP Flood |
| `drop-syn` | 过滤SYN包 | SYN Flood |
| `drop-icmp` | 过滤ICMP | ICMP Flood |
| `stop` | 完全停止抓包 | 极端情况 |

---

## 技术栈

<div align="center">

| <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/java/java-original.svg" width="40"/> | <img src="https://cdn.jsdelivr.net/gh/devicons/devicon/icons/spring/spring-original.svg" width="40"/> | <img src="https://img.shields.io/badge/WebSocket-010101?style=for-the-badge&logo=websocket" height="30"/> |
|:---:|:---:|:---:|
| **Java 17** | **Spring Boot 3.2.5** | **WebSocket** |

</div>

---

## 环境要求

- JDK 17+
- Maven 3.6+
- Npcap (Windows) — 安装时勾选 WinPcap 兼容模式
- **管理员/root 权限**

---

## 快速部署

```bash
git clone https://github.com/fkwhao/vp-shield-backend.git
cd vp-shield-backend

mvn clean package -DskipTests

# Windows (管理员CMD)
java -jar target/vp-shield-0.0.1-SNAPSHOT.jar

# Linux (root)
sudo java -jar target/vp-shield-0.0.1-SNAPSHOT.jar
```

访问 `http://localhost:8080`，WebSocket `ws://localhost:8080/ws/traffic`

---

## API 端点

### 抓包
```
POST /api/v1/capture/start        启动
POST /api/v1/capture/stop         停止
GET  /api/v1/capture/status       状态
GET  /api/v1/interfaces           网卡列表
```

### 封禁
```
GET    /api/v1/block/list         封禁列表
DELETE /api/v1/block/{ip}         解封
POST   /api/v1/block/clear        清空
POST   /api/v1/block/sync         同步防火墙
```

### 限速
```
GET  /api/v1/ratelimit/status     状态
POST /api/v1/ratelimit/disable    禁用(恢复)
```

### 紧急防御
```
GET  /api/v1/emergency/status     紧急防御状态
POST /api/v1/emergency/trigger    手动触发紧急防御
POST /api/v1/emergency/recover    退出紧急防御模式
```

### 统计
```
GET /api/v1/stats/current         实时统计
GET /api/v1/stats/history         历史数据
GET /api/v1/defense/attack-sources 攻击源
```

### 配置
```
GET /api/v1/config                获取完整配置
PUT /api/v1/config                更新配置(运行时)
```

---

## 配置参数

```yaml
vpshield:
  defense:
    icmp-reply-threshold: 100     # ICMP Reply阈值(pps)
    tcp-syn-threshold: 1000       # SYN阈值(pps)
    udp-threshold: 5000           # UDP阈值(pps)
    alert-cooldown-ms: 30000      # 告警冷却(ms)
    auto-block: false             # 自动封禁开关
    block-duration-minutes: 60    # 封禁时长
    rate-limit: true              # 限速开关
    auto-block-window-seconds: 30 # 封禁窗口
    auto-block-attack-threshold: 3# 封禁阈值
    # 紧急防御配置
    emergency-defense: true       # 紧急防御开关
    emergency-source-ip-threshold: 50  # 触发阈值:源IP数量(单一IP攻击优先封禁)
    emergency-pps-threshold: 10000     # 触发阈值:PPS
    emergency-stop-capture: false      # 是否停止抓包
    emergency-recovery-seconds: 120    # 自动恢复时间
```

---

## 架构

```
com.ethan.vpshield
│
├─ controller
│   ├─ ShieldController           REST API
│   └─ TrafficWebSocketHandler    实时推送
│
├─ service
│   ├─ SnifferService             抓包引擎
│   ├─ DefenseMonitor             检测核心
│   └─ defense/
│       ├─ IpBlocker              防火墙联动
│       ├─ RateLimitStrategy      限速策略
│       ├─ SynFloodDefenseStrategy
│       ├─ UdpFloodDefenseStrategy
│       ├─ SmurfDefenseStrategy
│       └─ IcmpFloodDefenseStrategy
│
├─ model
│   ├─ PacketInfo                 数据包模型
│   ├─ TrafficStats               统计模型
│   └─ Alert                      告警模型
```

---

## 策略选择

| 攻击来源 | auto-block | rate-limit | 效果 |
|---------|------------|------------|-----|
| 真实IP (内网) | `true` | `false` | 精准封禁攻击源 |
| 伪造IP (外网DDoS) | `false` | `true` | 限速保护服务 |
| 大规模DDoS | 启用 `emergency-defense` | - | 动态过滤攻击协议 |

---

## 测试验证

```bash
# SYN Flood
hping3 -S -p 80 --flood <target>

# UDP Flood  
hping3 -2 -p 53 --flood <target>

# ICMP Flood
hping3 -1 --flood <target>

# Smurf (广播放大)
hping3 -1 --flood <broadcast> -a <victim_ip>
```

---

## 注意事项

- 防火墙操作需要管理员权限
- Windows 使用 `netsh advfirewall`
- Linux 使用 `iptables`
- 封禁规则命名格式: `VP-Shield-Block-{ip}`
- 服务重启自动清理残留规则
- 紧急防御通过动态BPF过滤器实现，不影响防火墙规则

---

## License

MIT

**fkwhao**