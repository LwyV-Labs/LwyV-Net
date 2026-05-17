# LwyV-Net

LwyV-Net 是一个轻量的私有网络 / 虚拟局域网项目。它通过 TUN 虚拟网卡、加密 TCP 隧道、虚拟 DHCP 和服务端网关转发，把分散在不同网络环境里的设备接入到同一个三层网络中。

当前项目重点不是做成复杂平台，而是提供一个清晰、可控、方便二次开发的组网核心。它可以作为远程设备接入、移动端 VPN、边缘节点互联、Web 管理平台的底层网络能力。

## 当前能力

- TUN 虚拟网卡收发三层 IP 包。
- TCP 加密隧道，支持客户端到服务端的安全连接。
- X25519 静态密钥认证与会话加密。
- vDHCP 自动下发虚拟 IP、网关、MTU、DNS。
- 客户端可通过服务端网关代理访问外部网络。
- 服务端可统计在线客户端、虚拟 IP、流量速率。
- 服务端提供 management HTTP API，方便后续接 Web 监控平台。
- Android 侧提供 gomobile 绑定入口，可打包为 AAR。

## 项目结构

```text
.
├── main.go                 # 程序入口：client / server / genkey
├── config/                 # client.json / server.json 配置加载与校验
├── tcpx/                   # TCP 加密连接、握手、会话、心跳
├── vlan/                   # 服务端/客户端组网核心、vDHCP 接入、management API
├── vdhcp/                  # 虚拟 DHCP 地址池、租约、报文
├── tunSetup/               # TUN 网卡、路由、DNS、NAT 配置
├── mobile/                 # Android gomobile 绑定封装
└── build/                  # 示例配置与构建输出目录
```

## 快速开始

程序会按启动模式读取当前目录下的配置文件：

- 服务端读取 `server.json`
- 客户端读取 `client.json`

可以先从示例配置复制：

```bash
copy build\server.json server.json
copy build\client.json client.json
```

生成密钥：

```bash
go run . genkey
```

把服务端生成的 `publicKey` 填到客户端配置 `serverPublicKey`。`privateKey` 如果留空，程序启动时会自动生成并写回配置文件。

启动服务端：

```bash
go run . server
```

启动客户端：

```bash
go run . client
```

不传参数时默认以客户端模式启动。

## 配置说明

服务端核心配置在 `server.json`：

```json
{
  "privateKey": "",
  "port": 443,
  "ifName": "LwyV-Gateway",
  "mtu": 1300,
  "proxy": true,
  "vdhcp": {
    "startIP": "172.30.0.10",
    "endIP": "172.30.0.200",
    "subnetMask": "255.255.255.0",
    "gateway": "172.30.0.254",
    "dns": ["8.8.8.8", "1.1.1.1"]
  },
  "management": {
    "enabled": true,
    "addr": "127.0.0.1:18080",
    "token": ""
  }
}
```

客户端核心配置在 `client.json`：

```json
{
  "ifName": "LwyV-NetAdapter",
  "privateKey": "",
  "proxy": true,
  "server": "server-ip:443",
  "serverPublicKey": "server-public-key"
}
```

## Management HTTP API

服务端可以开启 management HTTP API，用于 Web 监控平台或调试工具读取运行状态。

默认建议只监听本机：

```json
{
  "management": {
    "enabled": true,
    "addr": "127.0.0.1:18080",
    "token": ""
  }
}
```

当前接口：

```text
GET /api/status
GET /api/peers
GET /api/traffic
GET /api/vdhcp/leases
GET /api/events
```

如果配置了 `token`，请求需要带认证头：

```bash
curl -H "Authorization: Bearer your-token" http://127.0.0.1:18080/api/status
```

也可以使用：

```bash
curl -H "X-Management-Token: your-token" http://127.0.0.1:18080/api/status
```

如果需要远程调试，推荐使用 VSCode Remote SSH 的端口转发或 SSH 本地转发，不建议直接把 management API 暴露到公网。

## 打包

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

## 后续方向

- Web 管理平台：节点列表、在线客户端、流量图表、事件日志。
- 控制 API：踢客户端、释放租约、拉黑设备、热重载部分配置。
- 多节点管理：中心控制面统一监控多个 LwyV-Net 节点。
- 权限体系：只读 token、管理 token、操作审计。
- 更完整的 Windows / Android 客户端体验。

## License

MIT License. See [LICENSE](./LICENSE).
