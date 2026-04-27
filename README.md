# VP-Shield 网络安全监控系统

> 基于 Spring Boot + Pcap4j 的实时网络流量监控与攻击防御系统

---

## 核心能力

### 流量捕获
- Pcap4j 底层网络包捕获，支持混杂模式
- 自动解析 IP/ICMP/TCP/UDP 协议及 TCP 标志位
- 独立线程运行，零阻塞主进程

### 攻击检测

| 攻击类型 | 检测条件 | 描述 |
|---------|---------|------|
| SYN Flood | TCP SYN > 1000 pps | TCP 半开连接攻击 |
| UDP Flood | UDP > 5000 pps | UDP 洪水攻击 |
| Smurf | ICMP Reply > 100 pps + 多源IP | 广播放大攻击 |
| ICMP Flood | ICMP 异常流量 | ICMP 洪水攻击 |
| 异常流量 | PPS > 10000 + 少量源IP | 通用 DoS 攻击 |

### 防御策略

**IP 封禁** - 适用于真实 IP 攻击
- 自动封禁攻击源，调用系统防火墙阻断
- 支持 Windows/Linux，可配置封禁时长

**流量限速** - 适用于伪造 IP 攻击
- 按攻击类型智能限速（SYN/UDP/ICMP）
- 不依赖真实 IP，攻击停止后可恢复

**自动封禁机制**
- 时间窗口内攻击次数统计
- 同一 IP 多次攻击自动封禁
- 防止告警风暴

### 实时监控
- WebSocket 推送流量统计（PPS/带宽）
- 告警信息即时推送
- 攻击源 IP 追踪

---

## 技术栈

| 组件 | 版本 | 说明 |
|-----|------|-----|
| Java | 17 | JDK |
| Spring Boot | 3.2.5 | 框架 |
| Pcap4j | 1.8.2 | 抓包库 |
| WebSocket | - | 实时通信 |

---

## 环境要求

- JDK 17+
- Maven 3.6+
- Npcap/WinPcap (Windows)
- **管理员权限**（防火墙操作）

### 安装 Npcap
1. 下载 [Npcap](https://npcap.com/)
2. 安装时勾选 "Install Npcap in WinPcap API-compatible Mode"
3. 重启

---

## 快速开始

```bash
# 克隆
git clone https://github.com/fkwhao/vp-shield-backend.git
cd vp-shield-backend

# 编译
mvn clean package -DskipTests

# 运行（需管理员权限）
java -jar target/vp-shield-0.0.1-SNAPSHOT.jar
```

服务地址：`http://localhost:8080`

---

## API

### 抓包控制
```
POST /api/v1/capture/start       # 启动抓包
POST /api/v1/capture/stop        # 停止抓包
GET  /api/v1/capture/status      # 抓包状态
```

### 封禁管理
```
GET    /api/v1/block/list        # 封禁列表
DELETE /api/v1/block/{ip}        # 解封IP
POST   /api/v1/block/clear       # 清空封禁
```

### 限速管理
```
GET  /api/v1/ratelimit/status    # 限速状态
POST /api/v1/ratelimit/disable   # 禁用限速
```

### 流量统计
```
GET /api/v1/stats/current        # 当前统计
GET /api/v1/stats/history        # 历史统计
```

### 防御配置
```
GET/PUT /api/v1/defense/threshold      # 检测阈值
GET     /api/v1/defense/attack-sources # 攻击源
GET     /api/v1/defense/strategies     # 防御策略
```

---

## 配置

```yaml
vpshield:
  capture:
    interface-name: ""           # 网卡（空=自动）
    promiscuous: true            # 混杂模式
    buffer-size: 65536           # 缓冲区
    read-timeout: 100            # 超时(ms)

  defense:
    icmp-reply-threshold: 100    # ICMP阈值(pps)
    tcp-syn-threshold: 1000      # SYN阈值(pps)
    udp-threshold: 5000          # UDP阈值(pps)
    stats-window-ms: 1000        # 统计窗口
    alert-cooldown-ms: 30000     # 告警冷却
    auto-block: false            # 自动封禁
    block-duration-minutes: 60   # 封禁时长
    rate-limit: true             # 流量限速
    auto-block-window-seconds: 30
    auto-block-attack-threshold: 3
    repeat-attack-block: true
```

---

## 项目结构

```
src/main/java/com/ethan/vpshield/
├── config/           # 配置
├── controller/       # 控制器
├── dto/              # DTO
├── model/            # 模型
├── service/
│   ├── SnifferService.java        # 抓包
│   ├── DefenseMonitor.java        # 检测
│   ├── AttackEngine.java          # 攻击模拟
│   └── defense/
│       ├── IpBlocker.java         # IP封禁
│       ├── RateLimitStrategy.java # 限速
│       ├── SynFloodDefenseStrategy.java
│       ├── UdpFloodDefenseStrategy.java
│       ├── SmurfDefenseStrategy.java
│       └── IcmpFloodDefenseStrategy.java
└── VpShieldApplication.java
```

---

## 防御策略选择

| 场景 | auto-block | rate-limit | 说明 |
|-----|------------|------------|-----|
| 真实IP攻击 | true | false | 封禁攻击源 |
| 伪造IP攻击 | false | true | 限速防护 |

---

## 测试

```bash
# SYN Flood
sudo hping3 -S -p 80 --flood <target>

# UDP Flood
sudo hping3 -2 -p 53 --flood <target>

# ICMP Flood
sudo hping3 -1 --flood <target>
```

---

## License

MIT

---

> Author: fkwhao