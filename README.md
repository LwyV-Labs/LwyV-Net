# LwyV-Net

> 轻量、可控、面向公网环境的私有网络方案。  
> 通过 TUN 虚拟网卡 + 加密隧道 + 中继转发，把分散设备快速拉入同一个“可用内网”。

[![Go Version](https://img.shields.io/badge/Go-1.20%2B-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](./LICENSE)

---

## 项目简介

LwyV-Net 的目标不是“复杂的大而全平台”，而是提供一个**可以快速落地、便于二次开发**的组网基础能力：

- 在公网和复杂网络环境下，实现异地设备三层互通。
- 通过加密握手与会话保护公网传输安全。
- 以较少配置完成服务端/客户端部署与接入。
- 提供可扩展的中继与网关能力，支持后续工程化演进。

适用场景：IoT 设备维护、边缘节点管理、机器人协同、跨地域开发测试网络。

---

## 核心优势

- **轻量可控**：核心链路清晰，依赖少，方便定位与调试。
- **安全传输**：Noise IK 风格握手与会话加密（X25519 + HKDF-SHA256 + ChaCha20-Poly1305）。
- **组网门槛低**：内置虚拟 DHCP，减少手动地址管理成本。
- **韧性连接**：支持断线重连与会话轮换，提升复杂网络下可用性。
- **可扩展架构**：已具备网关/NAT 方向能力，可继续演进策略与控制面。

---
### win打包
```bash
go build -o ./build/lwyvnet.exe main.go
```
### linux打包
```bash
$env:CGO_ENABLED=0; $env:GOOS="linux";go build -o ./build/lwyvnet-linux-amd64 main.go                 
```

### android打包aar
```bash
go mod tidy; 
go install golang.org/x/mobile/cmd/gomobile@latest; 
go install golang.org/x/mobile/cmd/gobind@latest; 
gomobile clean; 
gomobile init; 
New-Item -ItemType Directory -Force build | Out-Null; 
gomobile bind -v -target android -androidapi 23 -o build/lwyvnet.aar -javapkg "com.lwyv.net" ./mobile
```

## 当前能力（Now）

- ✅ TUN 虚拟网卡接入（三层 IP 收发）
- ✅ TCP 隧道通信（客户端 ↔ 服务端）
- ✅ Noise IK 风格握手与会话加密
- ✅ 虚拟 DHCP 自动分配地址
- ✅ 断线重连与会话轮换
- ✅ 可选代理模式（客户端默认流量可经隧道转发，服务端可做网关/NAT）

> 当前版本可用于基础跨地域设备互联、远程访问与内网化接入。

---

## 发展方向（Roadmap）

### 连接与可靠性
- 🔜 链路质量探测与智能切换
- 🔜 多中继容灾与自动降级
- 🔜 更完善的 TCP 链路优化与重传控制策略

### 平台与工程化
- 🔜 多平台完善（Windows / Linux / macOS / Android）
- 🔜 中继节点池与调度能力
- 🔜 更完善的部署与运维工具链

### 管理与可观测
- 🔜 Web 管理后台（设备、节点、密钥、权限）
- 🔜 链路健康与流量监控
- 🔜 可审计的访问控制策略

---

## 打包
```bash
go build -trimpath -buildvcs=false -ldflags="-s -w" -o build/LwyV-Net.exe .

$env:CGO_ENABLED=0; $env:GOOS="linux"; $env:GOARCH="amd64";go build -trimpath -buildvcs=false -ldflags="-s -w" -o build/LwyV-Net .

```

## 快速运行

程序按启动模式读取当前目录下的配置：服务端读取 `server.json`，客户端读取 `client.json`。

### 1) 准备配置

```bash
cp build/server.json server.json
cp build/client.json client.json
```

### 2) 编译

```bash
go build -o build/lwyv-net .
```

### 3) 初始化密钥（建议两端都执行）

```bash
./build/lwyv-net genkey
```

把输出的 `publicKey` 互相填入对端对应配置文件（`server.json` 或 `client.json`）的 `common.peerPublicKeys`。

### 4) 启动服务端

```bash
sudo ./build/lwyv-net server
```

### 5) 启动客户端

```bash
sudo ./build/lwyv-net client 1

```

> 不传参数默认按客户端启动并连接第1个服务端，即 `./build/lwyv-net` 等同于 `./build/lwyv-net client 1`。

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
