# LwyV-Net

> 一个面向公网环境的私域网络基础设施：通过虚拟网卡、加密隧道与中继能力，把分散设备组织成可控、可扩展、低门槛的“软件定义内网”。

[![Go Version](https://img.shields.io/badge/Go-1.20%2B-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

---

## 项目愿景

LwyV-Net 的目标不是“再做一个 VPN 工具”，而是成为 **下一代设备互联（IoT / 机器人 / 自动驾驶与移动终端）的基础网络层**：

- 在复杂公网环境中构建稳定的私域连接；
- 为设备到设备、设备到云、边缘到边缘提供统一组网能力；
- 逐步演进为像 Docker 一样易用、可标准化、可规模化的开源基础设施。

如果你关注“让海量异构设备在公网下像局域网一样协同”，这个项目正是为此而生。

---

## 当前已实现（Now）

- ✅ **TUN 虚拟网卡驱动接入**
- ✅ **三层 IP 数据包抓取与解析**
- ✅ **加密转发与中转代理**
- ✅ **异地虚拟局域网组网（类 VPN）**
- ✅ **双传输协议支持：TCP / KCP**
- ✅ **断线重连机制与连接稳定性优化**
- ✅ **虚拟 DHCP 自动分配 IP**
- ✅ **服务端流量代理能力**

> 以上能力已可支撑基础的跨地域设备互联与内网化访问场景。

---

## 未来规划（Roadmap）

### 网络与连接能力
- 🔜 NAT 穿透（UDP 打洞）
- 🔜 P2P 直连（降低中转延迟与带宽成本）
- 🔜 智能链路选择、自动降级与重试

### 平台与工程化
- 🔜 多平台全面适配：Windows / Linux / macOS / Android
- 🔜 中继节点部署体系（节点池、调度、容灾）
- 🔜 节点优选与基础负载均衡

### 管理与可观测性
- 🔜 Web 管理后台：设备、节点、权限、密钥配置
- 🔜 流量监控与链路健康状态面板
- 🔜 可审计的网络策略与访问控制

---

## 典型应用场景

- **物联网（IoT）**：海量设备跨网络环境稳定接入与远程维护
- **机器人系统**：多机器人协同、远程控制、边云联动
- **自动驾驶/骑行等移动终端**：车端/路侧/云端安全互通
- **分布式边缘计算**：跨站点服务发现、控制通道、数据回传
- **开发测试网络**：快速搭建“跨地域实验内网”

---

## 架构流程（简化）

```text
应用程序
  ↓
操作系统协议栈
  ↓
TUN 虚拟网卡
  ↓
LwyV-Net 数据面（抓包/封包/加密）
  ↓
TCP / KCP 隧道
  ↓
服务端中继 / 目标端
  ↓
对端解封装并写回 TUN
  ↓
对端协议栈与应用
```

---

## 加密流程（补充说明）

> 当前数据面加密由 `vlan/secure/session.go` 实现，采用 **Noise IK 风格握手 + X25519 + HKDF-SHA256 + ChaCha20-Poly1305(AEAD)**。

### 1) 身份与密钥准备

- 双端都使用 32 字节 Curve25519 静态私钥（配置中为 Base64），启动时解析得到静态公钥；
- 设备标识 `deviceID` 由对端静态公钥做 SHA-256 后取前 8 字节生成（用于日志与会话识别）；
- 握手时每一轮会生成新的会话 `keyID`（客户端/服务端分别自增）。

### 2) 握手阶段（建立会话密钥）

客户端（Initiator）：
1. 生成一次性临时密钥对 `ephPriv/ephPub`；
2. 发送握手初始化帧：`clientEphPub(32B) + clientStaticPub(32B)`（`PacketTypeHandshakeInit`）；
3. 接收服务端响应帧：`serverEphPub(32B)`（`PacketTypeHandshakeResp`）；
4. 计算 3 组共享密钥材料：`es`、`se`、`ee`。

服务端（Responder）：
1. 接收并解析客户端 `clientEphPub + clientStaticPub`；
2. （可选）若配置了 `peerPublicKey` 或 `peerPublicKeys`，校验是否为允许的对端静态公钥（白名单）；
3. 生成自己的临时密钥并回传 `serverEphPub`；
4. 同样计算 `es`、`se`、`ee`。

### 3) 会话密钥派生

- 将协议名 `lwyv-net-ik-v1` 与 `es/se/ee` 拼接为输入材料；
- 使用 HKDF-SHA256（info=`transport`）拉取两把 32 字节对称密钥 `k1/k2`；
- 发起方使用：`send=k1, recv=k2`；响应方反向使用：`send=k2, recv=k1`。

这样可以保证同一条隧道两端的收发密钥方向相反，避免同密钥双向复用。

### 4) 数据加密封装（Secure Frame）

每个加密包结构如下：

```text
[ keyID(4B) | counter(8B) | innerType(1B) | ciphertext+tag ]
```

- `keyID`：标记当前会话版本，便于轮换时兼容旧会话；
- `counter`：发送方向单调递增计数器；
- `innerType`：内层业务类型（例如 IP 包、VDHCP 消息等）；
- `ciphertext+tag`：ChaCha20-Poly1305 输出，认证数据（AAD）为前 13 字节头部。

Nonce 构造方式：使用 AEAD Nonce 长度（ChaCha20-Poly1305 为 12 字节），后 8 字节写入 `counter`，前部补 0。

### 5) 解密与重放保护

- 收包先根据 `keyID` 在 `SessionManager` 中匹配当前会话；若不匹配则尝试上一轮会话（平滑轮换）；
- 校验 `counter` 必须严格大于已接收最大值，否则判定为重放并丢弃；
- 通过 AEAD `Open` 验证并解密，失败即丢包。

### 6) 会话轮换机制

- 每次重连/重新握手都会生成新的 `keyID` 与新会话；
- `SessionManager.Rotate(next)` 会把旧会话降级为 `previous`，新会话设为 `current`；
- 解密阶段允许 `current + previous` 双会话并行，降低切换瞬间丢包风险。

> 说明：代码中预留了 `RekeyInterval = 120s` 常量，当前版本主要在“重连或重握手”时触发换钥，后续可扩展为定时主动轮换。

---

## 快速开始

### 1) 构建

```bash
go build -o build/vlan.exe
```

Linux 交叉编译：

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o build/vlan.bin
```

### 2) 启动服务端

```bash
chmod +x build/vlan.bin
sudo ./build/vlan.bin server
```

后台运行（可选）：

```bash
sudo nohup ./build/vlan.bin server > server.log 2>&1 &
```

### 3) 启动客户端

```bash
./build/vlan.bin
```

> 实际启动参数与配置项请结合源码中的配置模块进行调整（如节点地址、密钥、协议选择）。

---

## 项目结构

```text
.
├── main.go                # 程序入口、
├── secure/                # Noise IK 风格握手、会话密钥轮换与 AEAD 封装
├── vlan/                  # 核心组网、隧道、路由、客户端/服务端逻辑
├── vdhcp/                 # 虚拟 DHCP 管理与分配
├── wintun/                # Windows TUN 依赖与头文件
└── build/                 # 构建产物与配置样例
```

---

## 开源与共建

LwyV-Net 目前处于持续演进阶段，非常欢迎你通过以下方式参与：

- 提交 Issue：反馈 bug、使用场景与需求；
- 提交 PR：协议优化、稳定性改进、平台适配；
- 参与设计讨论：NAT 穿透、P2P、控制面架构、可观测性体系。

如果你也认同“公网上的私域网络将成为未来设备网络基础设施”，欢迎一起把它打造成开源标杆。

---

## License

MIT License. See [LICENSE](./LICENSE).
