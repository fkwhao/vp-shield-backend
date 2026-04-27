<div align="center">

# 🛡️ VP-Shield

**网络安全监控系统**

基于 Spring Boot + Pcap4j 的实时网络流量监控与攻击防御系统

[![Java](https://img.shields.io/badge/Java-17-orange.svg)](https://www.oracle.com/java/)
[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2.5-green.svg)](https://spring.io/projects/spring-boot)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

</div>

---

## ✨ 功能特性

### 🔍 流量捕获
- 基于 Pcap4j 的底层网络包捕获
- 支持混杂模式，捕获所有经过网卡的数据包
- 自动解析 IP、ICMP、TCP、UDP 等协议
- TCP 标志位解析（SYN、ACK、FIN、RST 等）
- 独立线程运行，不阻塞主进程

### 🚨 多类型攻击检测

| 攻击类型 | 检测条件 | 说明 |
|:--------:|:--------:|:----:|
| **SYN Flood** | TCP SYN > 1000 pps | TCP 半开连接攻击 |
| **UDP Flood** | UDP > 5000 pps | UDP 洪水攻击 |
| **Smurf 攻击** | ICMP Reply > 100 pps + 多源 IP | 广播放大攻击 |
| **ICMP Flood** | ICMP 异常流量 | ICMP 洪水攻击 |
| **异常流量** | 总 PPS > 10000 + 少量源 IP | 通用 DoS 攻击 |

### 🛡️ 多策略防御

#### 📌 IP 封禁策略（适用于真实 IP 攻击）
- 自动封禁攻击源 IP
- 调用系统防火墙添加阻断规则
- 支持 Windows/Linux 双平台
- 可配置封禁时长，支持自动解封

#### ⚡ 流量限速策略（适用于伪造 IP 攻击）
- 根据攻击类型智能限速
- SYN Flood → 限制 TCP SYN 包速率
- UDP Flood → 限制 UDP 包速率
- ICMP Flood → 限制 ICMP 包速率
- 攻击停止后可手动恢复正常

#### 🔁 自动封禁机制
- 基于时间窗口的攻击次数统计
- 同一 IP 在窗口内多次攻击自动封禁
- 防止告警风暴，避免重复处理

### 📊 实时监控
- WebSocket 实时推送流量统计
- PPS、带宽占用实时展示
- 告警信息即时推送
- 攻击源 IP 追踪

### 🧪 回环测试
- 模拟攻击流量验证检测逻辑
- 无需真实网络环境即可测试
- 可配置模拟包数量和攻击源数量

---

## 🛠️ 技术栈

| 技术 | 版本 | 说明 |
|:-----|:----:|:-----|
| Java | 17 | JDK 版本 |
| Spring Boot | 3.2.5 | 基础框架 |
| Pcap4j | 1.8.2 | 网络包捕获库 |
| WebSocket | - | 实时通信 |
| Lombok | - | 代码简化 |

---

## 📦 环境要求

- **JDK 17+**
- **Maven 3.6+**
- **Npcap / WinPcap**（Windows）
- **管理员权限**（防火墙操作需要）

### 安装 Npcap (Windows)

1. 下载 [Npcap](https://npcap.com/)
2. 安装时勾选 **"Install Npcap in WinPcap API-compatible Mode"**
3. 重启系统

---

## 🚀 快速开始

### 1. 克隆项目
```bash
git clone https://github.com/fkwhao/vp-shield-backend.git
cd vp-shield-backend
```

### 2. 编译项目
```bash
mvn clean package -DskipTests
```

### 3. 运行应用（需管理员权限）
```bash
# Windows: 以管理员身份运行 CMD/PowerShell
java -jar target/vp-shield-0.0.1-SNAPSHOT.jar

# Linux: 使用 sudo
sudo java -jar target/vp-shield-0.0.1-SNAPSHOT.jar
```

### 4. 访问服务
- 服务地址：`http://localhost:8080`
- WebSocket：`ws://localhost:8080/ws/traffic`

---

## 📖 API 文档

### 网络接口
```
GET  /api/v1/interfaces          # 获取可用网卡列表
```

### 抓包控制
```
POST /api/v1/capture/start       # 启动抓包
POST /api/v1/capture/stop        # 停止抓包
GET  /api/v1/capture/status      # 获取抓包状态
```

### 封禁管理
```
GET    /api/v1/block/list        # 获取封禁 IP 列表
DELETE /api/v1/block/{ip}        # 解封指定 IP
POST   /api/v1/block/clear       # 清空所有封禁
POST   /api/v1/block/sync        # 同步清理防火墙规则
```

### 限速管理
```
GET  /api/v1/ratelimit/status    # 获取限速状态
POST /api/v1/ratelimit/disable   # 禁用限速（恢复正常）
```

### 流量统计
```
GET /api/v1/stats/current        # 获取当前流量统计
GET /api/v1/stats/history        # 获取历史流量统计
```

### 防御配置
```
GET/PUT /api/v1/defense/threshold     # 获取/更新检测阈值
GET     /api/v1/defense/attack-sources # 获取检测到的攻击源
GET     /api/v1/defense/strategies     # 获取支持的防御策略
```

### 系统状态
```
GET /api/v1/status               # 获取系统整体状态
GET /api/v1/health               # 健康检查
```

---

## ⚙️ 配置说明

```yaml
vpshield:
  capture:
    interface-name: ""           # 网卡名称（空则自动选择）
    promiscuous: true            # 混杂模式
    buffer-size: 65536           # 缓冲区大小
    read-timeout: 100            # 读取超时(ms)

  defense:
    icmp-reply-threshold: 100    # ICMP Reply 阈值(包/秒)
    tcp-syn-threshold: 1000      # TCP SYN 阈值(包/秒)
    udp-threshold: 5000          # UDP 阈值(包/秒)
    stats-window-ms: 1000        # 统计窗口(ms)
    alert-cooldown-ms: 30000     # 告警冷却(ms)
    auto-block: false            # 自动封禁开关
    block-duration-minutes: 60   # 封禁时长(分钟)
    rate-limit: true             # 流量限速开关
    rate-limit-recovery-seconds: 60  # 限速恢复时间(秒)
    auto-block-window-seconds: 30    # 自动封禁时间窗口(秒)
    auto-block-attack-threshold: 3   # 窗口内攻击次数阈值
    repeat-attack-block: true        # 重复攻击自动封禁
```

---

## 📁 项目结构

```
src/main/java/com/ethan/vpshield/
├── config/                      # 配置类
│   ├── AsyncConfig.java
│   ├── ShieldProperties.java
│   └── WebSocketConfig.java
├── controller/                  # 控制器层
│   ├── ShieldController.java
│   ├── TrafficWebSocketHandler.java
│   └── GlobalExceptionHandler.java
├── dto/                         # 数据传输对象
├── model/                       # 数据模型
│   ├── Alert.java
│   ├── PacketInfo.java
│   ├── TrafficStats.java
│   └── NetworkInterface.java
├── service/                     # 核心服务
│   ├── SnifferService.java      # 流量捕获
│   ├── DefenseMonitor.java      # 防御检测
│   ├── AttackEngine.java        # 攻击模拟
│   ├── LoopbackTestService.java # 回环测试
│   └── defense/                 # 防御策略
│       ├── DefenseStrategy.java
│       ├── DefenseStrategyManager.java
│       ├── IpBlocker.java
│       ├── RateLimitStrategy.java
│       ├── SynFloodDefenseStrategy.java
│       ├── SmurfDefenseStrategy.java
│       ├── IcmpFloodDefenseStrategy.java
│       └── UdpFloodDefenseStrategy.java
└── VpShieldApplication.java
```

---

## 💡 防御策略对比

| 策略 | 适用场景 | 优点 | 缺点 |
|:----:|:--------:|:----:|:----:|
| **IP 封禁** | 真实 IP 攻击 | 彻底阻断攻击源 | 对伪造 IP 无效 |
| **流量限速** | 伪造 IP 攻击 | 不依赖真实 IP | 可能影响正常流量 |

### 推荐配置

```yaml
# 针对真实 IP 攻击（如内网攻击）
auto-block: true
rate-limit: false

# 针对伪造 IP 攻击（如外部 DDoS）
auto-block: false
rate-limit: true
```

---

## 🧪 测试方法

### 使用 hping3 测试
```bash
# SYN Flood 测试
sudo hping3 -S -p 80 --flood <目标IP>

# UDP Flood 测试
sudo hping3 -2 -p 53 --flood <目标IP>

# ICMP Flood 测试
sudo hping3 -1 --flood <目标IP>
```

### 回环测试
通过 API 或前端界面启动回环测试，无需外部工具即可验证检测逻辑。

---

## ⚠️ 安全警告

**⚠️ 攻击模拟功能仅供授权安全研究和测试使用！**

- 请勿在未授权的网络环境中使用攻击功能
- 请勿对真实目标发起攻击
- 使用前请确保已获得相关授权

---

## 📄 许可证

[MIT License](LICENSE)

---

## 👥 贡献

欢迎提交 Issue 和 Pull Request！

---

<div align="center">

**Made with ❤️ by fkwhao**

</div>