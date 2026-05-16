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
gomobile bind -v -target android/arm64 -androidapi 23 -o build/lwyvnet.aar -javapkg "com.lwyv.net" ./mobile
```
我想用go封装一个tcp库， 分成服务端和客户端两个部分，
首先是报文部分，设计一个帧格式，分成四个部分，标识，版本，帧类型，以及长度，版本不匹配直接断开连接，标识不匹配也断开连接，帧类型有心跳帧，加密帧等
建立连接后，客户端自动ping服务端自动pong可以设置心跳间隔，并且心跳间隔不是固定的，而是可以设置一个基础值和一个随机范围值，心跳间隔会随机防止被检测到是心跳帧，
客户端服务端都有读写超时，便于检测长时间接收不到心跳就主动断开，实现循环读写指定长度，
加密部分支持自动加密会话，采样X25519 + AES-GCM + HKDF 的 Noise-IK 风格握手，实现定时自动更换会话密钥原密钥有一个过期时间，连接的时候客户端知道服务端公钥，建立连接后，自动进行加密操作，随后所有的数据交互都是加密后的内容，实现抗重放窗口，
最后就是客户端支持非主动断开的重连，不要搞多线程重连，确保连接唯一，并且断开连接或者，连接重连成功时可以通知上层。
在设计成尽量简单易懂，方便打包成库便于安卓kolite语言调用，最后实现一个客户端一个服务端的测试程序。

简单使用示例
conn, err := securetcp.NewClient(securetcp.ClientConfig{
Address:             c.conf.Server,
ClientPrivateKeyB64: c.conf.PrivateKey,
ServerPublicKeyB64:  c.conf.ServerPublicKey,
AutoReconnect:       true,
CommonConfig: securetcp.CommonConfig{
ReadTimeout:     10 * time.Second,
WriteTimeout:    8 * time.Second,
HeartbeatBase:   4 * time.Second,
HeartbeatJitter: 1 * time.Second,
RekeyInterval:   45 * time.Second,
OldKeyGrace:     20 * time.Second,
},
OnReconnect: func() {
c.reconnectInit()
},
})	
srv, err := securetcp.NewServer(securetcp.ServerConfig{
Address:             fmt.Sprintf(":%d", s.conf.Port),
ServerPrivateKeyB64: s.conf.PrivateKey,
CommonConfig: securetcp.CommonConfig{
ReadTimeout:     60 * time.Second,
WriteTimeout:    15 * time.Second,
HeartbeatBase:   10 * time.Second,
HeartbeatJitter: 5 * time.Second,
RekeyInterval:   45 * time.Second,
OldKeyGrace:     30 * time.Second,
},
})
配置文件如下
client.json
{
"privateKey": "7pzPHJheitgGTpkHSsW8ST6Q7/3hWCHknOt+XfvpsOg=",
"server": "64.83.34.53:443",
"serverPublicKey": "dfWVua+ZYFhQchiYyhgeYroFquD0bf98zHjG6YYv2kE=",
"ifName": "LwyV-NetAdapter",
"mtu": 1300,
"proxy": true
}
server.json
{
"privateKey": "Gdgdwua7wo4v6i7/kwAX7AVbM1gT5WEqWukjRAOsh00=",
"port": 443,
"ifName": "LwyV-Gateway",
"mtu": 1300,
"proxy": true,
"vdhcp": {
"startIP": "172.30.0.10",
"endIP": "172.30.0.200",
"subnetMask": "255.255.255.0",
"gateway": "172.30.0.254"
}
}
配置文件读取代码也已给出


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
