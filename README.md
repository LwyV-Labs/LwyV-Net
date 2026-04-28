# LwyV-Net

> 一个面向公网环境的轻量级私有网络方案：通过虚拟网卡、加密隧道和中继能力，把分散设备快速拉进同一个“可控内网”。

[![Go Version](https://img.shields.io/badge/Go-1.20%2B-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

---

## 项目能解决什么问题

LwyV-Net 主要解决“设备都在公网、网络环境复杂、但又希望像局域网一样互通”的问题：

- **异地设备互联困难**：不同地域、不同网络下的设备难以稳定互联。
- **远程维护成本高**：IoT、机器人、边缘设备运维依赖复杂网络配置。
- **公网传输安全性不足**：需要统一加密传输，避免明文暴露。
- **组网门槛高**：希望以较少配置快速搭建“可用内网”。

适用场景：IoT、机器人协同、边缘节点管理、跨地域开发测试网络。

---

## 当前已完成（Now）

- ✅ TUN 虚拟网卡接入（三层 IP 收发）
- ✅ UDP 隧道通信（客户端 ↔ 服务端）
- ✅ Noise IK 风格握手与会话加密（X25519 + HKDF-SHA256 + ChaCha20-Poly1305）
- ✅ 虚拟 DHCP 自动分配地址
- ✅ 断线重连与会话轮换
- ✅ 可选代理模式（客户端默认流量可经隧道转发，服务端可做网关/NAT）

> 当前版本已经可以支撑基础的跨地域设备互联和远程访问。

---

## 未来期望（Roadmap）

### 连接能力
- 🔜 NAT 穿透（UDP 打洞）
- 🔜 P2P 直连（降低中继延迟与带宽成本）
- 🔜 智能链路选择与自动降级

### 平台与工程化
- 🔜 多平台完善（Windows / Linux / macOS / Android）
- 🔜 中继节点池与调度能力
- 🔜 更完善的部署和运维工具链

### 管理与可观测性
- 🔜 Web 管理后台（设备、节点、密钥、权限）
- 🔜 链路健康与流量监控
- 🔜 可审计的访问控制策略

---

## 快速运行（保持简单）

程序默认读取当前目录下的 `config.yaml`。

### 1) 准备配置

```bash
cp build/config.yaml config.yaml
```

### 2) 编译

```bash
go build -o build/lwyv-net .
```

### 3) 初始化密钥（建议两端都执行）

```bash
./build/lwyv-net genkey
```

把输出的 `publicKey` 互相填入对端 `config.yaml` 的 `common.peerPublicKeys`。

### 4) 启动服务端

```bash
sudo ./build/lwyv-net server
```

### 5) 启动客户端

```bash
sudo ./build/lwyv-net client
```

> 不传参数默认按客户端启动，即 `./build/lwyv-net` 等同于 `./build/lwyv-net client`。

---

## 项目结构

```text
.
├── main.go        # 入口：genkey / server / client
├── vlan/          # 核心组网逻辑
├── secure/        # 握手与加密会话
├── vdhcp/         # 虚拟 DHCP
├── setup/         # TUN、路由与系统配置
└── build/         # 构建产物与配置示例
```

---

## License

MIT License. See [LICENSE](./LICENSE).
