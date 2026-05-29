# LwyV-Net

LwyV-Net 是一个轻量级、自托管的私有组网项目。它通过 TUN 虚拟网卡、加密 TCP 隧道、虚拟 DHCP 和服务端网关转发，把分散在不同网络环境里的设备接入到同一个三层虚拟网络中。

你可以把它理解成一个适合学习、实验和二次开发的“私有虚拟局域网底座”：服务端负责认证、转发、分配虚拟 IP 和提供管理 API；客户端负责连接服务端、创建虚拟网卡、接收服务端下发的网络配置并转发 IP 包。

> 当前项目仍处于开发阶段，适合个人实验、教学、比赛、课程设计、实验室内网接入和工程二次开发。它还没有经过完整安全审计，不建议直接承载高风险生产流量。

## 目录

- [项目能做什么](#项目能做什么)
- [30 秒理解运行原理](#30-秒理解运行原理)
- [运行前准备](#运行前准备)
- [快速开始](#快速开始)
- [配置文件说明](#配置文件说明)
- [Management HTTP API](#management-http-api)
- [打包构建](#打包构建)
- [项目结构](#项目结构)
- [常见问题](#常见问题)
- [后续方向](#后续方向)
- [License](#license)

## 项目能做什么

| 能力 | 当前状态 | 说明 |
| --- | --- | --- |
| 加密 TCP 隧道 | 已实现 | 客户端和服务端通过 tcpx 建立加密连接 |
| X25519 密钥认证 | 已实现 | 服务端有自己的密钥，客户端用服务端公钥校验连接 |
| TUN 虚拟网卡 | 已实现 | Windows / Linux 桌面侧使用 TUN 收发三层 IP 包 |
| vDHCP 自动分配地址 | 已实现 | 服务端给客户端下发虚拟 IP、网关、DNS、MTU |
| 客户端全局代理路由 | 已实现 | 客户端 `proxy=true` 时注入分裂默认路由 |
| 服务端网关 NAT | Linux 可用 | 服务端 `proxy=true` 时依赖 Linux `sysctl` / `iptables` |
| 客户端互通 | 已实现 | 服务端按虚拟 IP 把客户端之间的 IP 包转发到目标客户端 |
| Management API | 已实现 | 查询状态、在线节点、流量、租约和事件 |
| Android AAR | 已实现基础封装 | Android 侧使用 `VpnService`，Go 侧负责隧道、认证和 vDHCP |

适合的典型场景：

- 云服务器和本地电脑组成一个私有虚拟网络。
- 实验室、边缘设备、测试机跨网络统一接入。
- 学习 Go 网络编程、TUN、VPN、路由、DNS 和加密握手。
- 在此基础上继续开发 Windows 客户端、Android 客户端或 Web 管理平台。

## 30 秒理解运行原理

最小拓扑如下：

```text
客户端应用流量
   ↓
客户端 TUN / Android VPN 接口
   ↓
LwyV-Net Client
   ↓  加密 TCP 隧道
LwyV-Net Server
   ↓
目标客户端 / 服务端网关 NAT / Management API
```

启动后大致发生这些事：

1. 服务端读取 `server.json`，启动 TCP 监听、vDHCP 地址池和可选的 Management API。
2. 客户端读取 `client.json`，用 `serverPublicKey` 校验服务端身份。
3. 加密握手成功后，客户端发送身份认证信息。
4. 服务端认证成功后，通过 vDHCP 给客户端分配虚拟 IP、网关、DNS 和 MTU。
5. 客户端创建或配置 TUN 网卡，把本机流量转进加密隧道。
6. 服务端按目标 IP 转发数据包：目标是其他客户端就转发给客户端，目标是外网且服务端开启代理就走服务端 NAT。

几个关键词先记住：

| 名词 | 含义 |
| --- | --- |
| `privateKey` | 私钥，必须自己保存，不能发给别人。留空时程序会自动生成并写回配置文件 |
| `publicKey` | 公钥，可以发给对端使用。客户端需要填写服务端公钥 |
| `serverPublicKey` | 客户端配置中的服务端公钥，用来确认连到的是正确服务端 |
| vDHCP | 项目内置的“虚拟 DHCP”，负责自动分配虚拟 IP |
| `proxy` | 是否接管默认流量。服务端和客户端都开启时，客户端外网流量可以经服务端转发 |
| Management API | 服务端只读 HTTP API，用来查看在线客户端、流量、租约和事件 |

更完整的架构图见 [ARCHITECTURE.md](./ARCHITECTURE.md)。

## 运行前准备

### 基础要求

- Go 版本以 [go.mod](./go.mod) 为准，当前项目声明为 `go 1.26`。
- 运行目录下必须有配置文件：
  - 服务端模式读取 `server.json`
  - 客户端模式读取 `client.json`
- 创建 TUN、修改路由、设置 DNS、配置 NAT 都需要系统权限。

### 推荐运行环境

| 角色 | 推荐环境 | 权限 / 依赖 |
| --- | --- | --- |
| 服务端 | Linux 服务器 | 建议 root 运行；`proxy=true` 需要 `/dev/net/tun`、`iproute2`、`iptables`、`sysctl` |
| Windows 客户端 | Windows 10/11 | 以管理员权限运行；需要可用的 Wintun 环境 |
| Linux 客户端 | Linux | root 或具备 `CAP_NET_ADMIN`；需要 `/dev/net/tun` 和 `ip` 命令 |
| Android 客户端 | Android App | Kotlin/Java 侧创建 `VpnService`，Go mobile AAR 负责隧道逻辑 |

注意：

- 如果服务端运行在 Windows，建议先把 `server.json` 里的 `proxy` 设为 `false`。当前服务端网关 NAT 逻辑面向 Linux，`proxy=true` 会调用 Linux 的 `iptables` / `sysctl`。
- 如果服务端端口使用 `443`，Linux 下通常需要 root 或额外的端口绑定权限。测试时也可以改成 `8443`、`9999` 等高位端口。
- 示例配置里的 IP、密钥和服务器地址只用于演示，首次部署请替换成自己的值。

## 快速开始

下面以“Linux 服务端 + Windows/Linux 客户端”为例。所有命令都在项目根目录执行。

### 1. 准备配置文件

PowerShell：

```powershell
Copy-Item .\build\server.json .\server.json
Copy-Item .\build\client.json .\client.json
```

Bash：

```bash
cp build/server.json ./server.json
cp build/client.json ./client.json
```

程序只会读取当前运行目录下的 `server.json` / `client.json`，不会自动读取 `build/` 目录里的示例文件。

### 2. 生成服务端密钥

```bash
go run . genkey
```

输出类似：

```text
privateKey: <server-private-key>
publicKey:  <server-public-key>
```

把 `<server-private-key>` 填到服务端 `server.json` 的 `privateKey`：

```json
{
  "privateKey": "<server-private-key>"
}
```

把 `<server-public-key>` 填到客户端 `client.json` 的 `serverPublicKey`：

```json
{
  "serverPublicKey": "<server-public-key>"
}
```

也可以把 `privateKey` 留空。程序启动时会自动生成私钥并写回当前配置文件，同时在日志里打印对应公钥。新手更推荐显式生成并填写，流程更清楚。

### 3. 修改服务端配置

打开 `server.json`，重点确认这些字段：

```json
{
  "privateKey": "<server-private-key>",
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

最小需要理解：

- `port` 是客户端要连接的服务端端口，云服务器安全组和系统防火墙要放行这个端口。
- `proxy=true` 表示服务端会创建网关 TUN 并启用 NAT，让客户端可以把外网流量经服务端转发。
- `vdhcp.gateway` 是服务端在虚拟网络里的网关地址，不能和地址池里的客户端 IP 冲突。
- `management.addr` 建议保持 `127.0.0.1:18080`，不要直接暴露到公网。

如果只是先测试客户端能否接入、看 Management API、验证客户端之间互通，可以先把服务端 `proxy` 改成 `false`，这样不需要服务端配置 NAT。

### 4. 修改客户端配置

打开 `client.json`：

```json
{
  "ifName": "LwyV-NetAdapter",
  "privateKey": "",
  "proxy": true,
  "server": "YOUR_SERVER_IP:443",
  "serverPublicKey": "<server-public-key>"
}
```

最小需要改两项：

- `server`：改成你的服务端公网 IP 或域名，例如 `203.0.113.10:443`。
- `serverPublicKey`：填服务端生成的 `publicKey`。

`privateKey` 可以留空，第一次启动时会自动生成并写回 `client.json`。客户端私钥决定客户端身份，后续不要随便删除或替换，否则服务端会把它当成一个新设备并重新分配虚拟 IP。

### 5. 启动服务端

Linux 服务端推荐：

```bash
sudo go run . server
```

也可以先构建再运行：

```bash
go build -o build/lwyvnet .
sudo ./build/lwyvnet server
```

看到类似日志说明服务端已经起来：

```text
虚拟 DHCP 已启用
tcpx 服务端启动成功
等待客户端连接并转发 IP 包
Management API 已启用
```

### 6. 启动客户端

Windows 请使用“以管理员身份运行”的 PowerShell：

```powershell
go run . client
```

Linux 客户端：

```bash
sudo go run . client
```

不传参数时默认就是客户端模式，所以下面两条等价：

```bash
go run .
go run . client
```

客户端看到类似日志说明已经拿到虚拟地址：

```text
tcpx 握手成功
已发送 VDHCP DISCOVER
虚拟地址配置成功 ip=172.30.0.10 mask=255.255.255.0 gateway=172.30.0.254
```

### 7. 验证是否成功

在服务端本机查询 Management API：

```bash
curl http://127.0.0.1:18080/api/status
curl http://127.0.0.1:18080/api/peers
curl http://127.0.0.1:18080/api/vdhcp/leases
```

如果你在本地电脑上想访问远程服务器的 Management API，推荐用 SSH 本地转发：

```bash
ssh -L 18080:127.0.0.1:18080 user@YOUR_SERVER_IP
```

然后在本地访问：

```bash
curl http://127.0.0.1:18080/api/status
```

如果启动了两个客户端，可以用分配到的虚拟 IP 互相测试连通性，例如：

```bash
ping 172.30.0.11
```

如果服务端和客户端都开启 `proxy=true`，客户端的默认流量会尝试走服务端网关。此时可以在客户端访问网页或用 `curl` 检查出口 IP。

### 8. 停止程序

按 `Ctrl+C` 停止。程序会尝试清理客户端路由、DNS、服务端 NAT 规则和 TUN 资源。

## 配置文件说明

### 服务端 `server.json`

| 字段 | 是否必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `privateKey` | 否 | 空时自动生成 | 服务端 X25519 私钥。不要泄露 |
| `port` | 否 | `9999` | TCP 监听端口。示例配置使用 `443` |
| `ifName` | 否 | `LwyV-Gateway` | 服务端 TUN 网卡名称 |
| `mtu` | 否 | `1300` | 下发给客户端的 MTU，也用于服务端 TUN |
| `proxy` | 否 | `false` | 是否启用服务端网关 TUN 和 NAT |
| `vdhcp.startIP` | 否 | `172.19.0.10` | vDHCP 地址池起始 IP |
| `vdhcp.endIP` | 否 | `172.19.0.200` | vDHCP 地址池结束 IP |
| `vdhcp.subnetMask` | 否 | `255.255.255.0` | 虚拟网络子网掩码 |
| `vdhcp.gateway` | 否 | `172.19.0.254` | 虚拟网关 IP，通常是服务端 TUN 地址 |
| `vdhcp.dns` | 否 | `8.8.8.8`, `1.1.1.1` | 下发给客户端的 DNS |
| `management.enabled` | 否 | `false` | 是否开启 Management API |
| `management.addr` | 否 | `127.0.0.1:18080` | Management API 监听地址 |
| `management.token` | 否 | 空 | 非空时请求必须带 token |
| `tcp.*` | 否 | 内置默认值 | 连接超时、心跳、重连、密钥轮换等高级参数 |

`proxy` 的含义：

- `server.proxy=true`：服务端创建 TUN，配置虚拟网关地址，开启 Linux NAT/FORWARD 规则。
- `server.proxy=false`：服务端不作为外网网关，但仍可做认证、vDHCP、客户端之间的虚拟 IP 转发。

### 客户端 `client.json`

| 字段 | 是否必填 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `privateKey` | 否 | 空时自动生成 | 客户端 X25519 私钥，决定客户端身份 |
| `server` | 是 | 无 | 服务端地址，格式如 `203.0.113.10:443` |
| `serverPublicKey` | 是 | 无 | 服务端公钥，用于校验服务端身份 |
| `ifName` | 否 | `LwyV-NetAdapter` | 客户端 TUN 网卡名称 |
| `proxy` | 否 | `false` | 是否把默认流量导入 TUN |
| `tcp.*` | 否 | 内置默认值 | 连接超时、心跳、重连等高级参数 |

`proxy` 的含义：

- `client.proxy=true`：客户端会给服务端公网 IP 加一条例外路由，再把 `0.0.0.0/1` 和 `128.0.0.0/1` 指向 TUN，避免隧道连接被自己的代理路由套住。
- `client.proxy=false`：客户端只配置虚拟网卡地址，不接管默认路由。适合先测试虚拟网内互通。

要让客户端外网流量经服务端转发，通常需要同时满足：

- 服务端 `proxy=true`
- 客户端 `proxy=true`
- 服务端运行在支持当前 NAT 逻辑的 Linux 环境
- 服务器安全组、防火墙、内核转发和 `iptables` 可正常工作

### 密钥格式

项目接受 32 字节 X25519 密钥，编码可以是：

- 标准 base64
- raw base64
- base64url
- hex

`go run . genkey` 输出的是标准 base64，直接复制即可。

## Management HTTP API

Management API 是服务端的只读监控接口，适合接 Web 控制台、调试脚本或运维面板。

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

接口列表：

| 接口 | 说明 |
| --- | --- |
| `GET /api` | 返回当前可用接口列表 |
| `GET /api/status` | 服务端状态、启动时间、在线数量、总流量、vDHCP 配置 |
| `GET /api/peers` | 当前连接列表、虚拟 IP、远端地址、认证状态、流量 |
| `GET /api/traffic` | 聚合上传 / 下载流量 |
| `GET /api/vdhcp/leases` | vDHCP 租约快照 |
| `GET /api/events` | 服务端事件列表 |

如果 `management.token` 为空，请求不需要鉴权：

```bash
curl http://127.0.0.1:18080/api/status
```

如果配置了 token，请使用任意一种认证头：

```bash
curl -H "Authorization: Bearer your-token" http://127.0.0.1:18080/api/status
```

```bash
curl -H "X-Management-Token: your-token" http://127.0.0.1:18080/api/status
```

安全建议：

- 不要把 Management API 直接暴露到公网。
- 如果必须远程访问，优先使用 SSH 端口转发、VPN 内网访问或反向代理鉴权。
- 非本机监听时请务必设置 `management.token`。

## 打包构建

### Windows 可执行文件

PowerShell：

```powershell
go build -o .\build\lwyvnet.exe .
```

运行：

```powershell
.\build\lwyvnet.exe server
.\build\lwyvnet.exe client
.\build\lwyvnet.exe genkey
```

Windows 客户端需要管理员权限。运行目录还需要能加载 Wintun 相关组件；如果 TUN 创建失败，先检查 Wintun 环境和权限。

### Linux 可执行文件

在 Linux 本机：

```bash
go build -o ./build/lwyvnet-linux-amd64 .
```

在 Windows PowerShell 交叉编译 Linux amd64：

```powershell
$env:CGO_ENABLED = "0"
$env:GOOS = "linux"
$env:GOARCH = "amd64"
go build -o .\build\lwyvnet-linux-amd64 .
```

上传到服务器后：

```bash
chmod +x ./lwyvnet-linux-amd64
sudo ./lwyvnet-linux-amd64 server
```

### Android AAR

Android 侧需要自己实现 `VpnService`、权限申请、前台服务和 UI；Go mobile AAR 提供 `mobile.Client`，负责连接、认证、vDHCP 和 IP 包收发。

PowerShell 构建示例：

```powershell
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/cmd/gobind@latest
gomobile clean
gomobile init
New-Item -ItemType Directory -Force build | Out-Null
gomobile bind -v -target android -androidapi 23 -o build/lwyvnet.aar -javapkg "com.lwyv.net" ./mobile
```

移动端封装重点：

- Kotlin/Java 侧调用 `mobile.NewClient()` 创建客户端。
- Android 侧必须用 `VpnService.protect(fd)` 保护真实 TCP socket，否则全局 VPN 路由可能把隧道连接套进隧道自身。
- Go 侧通过回调 `OnAddress(ip, subnetMask, gateway, mtu, dnsServers)` 通知 Android 创建 VPN 接口。
- Android 创建 VPN fd 后调用 `AttachTun(fd, mtu)` 交给 Go 转发。

## 项目结构

```text
.
├── main.go                 # 程序入口：client / server / genkey
├── config/                 # client.json / server.json 配置加载、默认值、校验
├── tcpx/                   # 加密 TCP 连接、握手、帧、心跳、密钥轮换
├── vlan/                   # 服务端/客户端组网核心、认证、vDHCP、转发、Management API
├── vdhcp/                  # 虚拟 DHCP 地址池、租约、Discover/Offer/Nak 编解码
├── tunSetup/               # TUN 网卡、路由、DNS、客户端代理路由、服务端 NAT
├── mobile/                 # Android gomobile 绑定封装
├── build/                  # 示例配置与本地构建产物
├── ARCHITECTURE.md         # 更完整的架构说明
└── PROJECT_PROMOTION_QA.md # 项目介绍和对外宣传问答稿
```

建议阅读顺序：

1. [main.go](./main.go)：先看启动模式和程序生命周期。
2. [config/config.go](./config/config.go)：看配置文件怎么读取、默认值怎么补、私钥怎么自动生成。
3. [vlan/server.go](./vlan/server.go)：看服务端如何初始化 vDHCP、TUN、TCP 和 Management API。
4. [vlan/client.go](./vlan/client.go)：看客户端如何认证、申请地址、配置 TUN 和转发 IP 包。
5. [tunSetup/tun_route.go](./tunSetup/tun_route.go)：看客户端代理路由如何避免隧道自套。
6. [vlan/management.go](./vlan/management.go)：看 HTTP API 返回哪些状态。
7. [mobile/lwyvpn.go](./mobile/lwyvpn.go)：看 Android AAR 暴露给 Kotlin/Java 的接口。

## 常见问题

### 1. 启动时报 `加载配置文件失败 client.json/server.json`

程序只读取当前运行目录下的 `client.json` 或 `server.json`。先从 `build/` 复制示例配置到项目根目录，或者把配置文件放到可执行文件所在目录。

### 2. 客户端报 `client.serverPublicKey 不能为空`

先在服务端生成密钥：

```bash
go run . genkey
```

把输出里的 `publicKey` 填到客户端 `serverPublicKey`。

### 3. `privateKey` 留空可以吗

可以。程序会自动生成并写回配置文件。服务端或客户端身份都由私钥决定，所以生成后请保留配置文件，不要频繁删除。

### 4. 创建 TUN 失败

通常是权限或系统环境问题：

- Windows：使用管理员权限运行，并确认 Wintun 环境可用。
- Linux：确认 `/dev/net/tun` 存在，并用 root 或 `CAP_NET_ADMIN` 运行。
- 容器内运行：需要额外开放 `/dev/net/tun` 和网络管理权限。

### 5. 服务端 `proxy=true` 时报 NAT 或 iptables 错误

当前服务端网关 NAT 面向 Linux。请确认：

- 使用 Linux 服务端。
- root 运行。
- 系统存在 `iptables`、`ip`、`sysctl`。
- 内核允许 IPv4 转发。

如果只是测试连接，可以先把服务端 `proxy` 改成 `false`。

### 6. 客户端连上后访问不了外网

按顺序检查：

1. 服务端 `proxy` 是否为 `true`。
2. 客户端 `proxy` 是否为 `true`。
3. 服务端是否是 Linux 且 NAT 规则配置成功。
4. 服务端安全组和系统防火墙是否允许转发流量。
5. 客户端 DNS 是否被正确设置到 TUN 接口。

如果只想访问虚拟网内其他客户端，可以把客户端 `proxy` 设为 `false`。

### 7. Management API 返回 `unauthorized`

说明 `management.token` 非空，但请求没有带正确 token。使用：

```bash
curl -H "Authorization: Bearer your-token" http://127.0.0.1:18080/api/status
```

或：

```bash
curl -H "X-Management-Token: your-token" http://127.0.0.1:18080/api/status
```

### 8. 端口连不上

检查这些点：

- `client.json` 的 `server` 是否写成 `IP:端口`。
- 服务端 `server.json` 的 `port` 是否和客户端一致。
- 云服务器安全组是否放行该端口。
- Linux 防火墙是否放行该端口。
- 服务端进程是否真的启动成功。

### 9. 为什么示例配置里已有密钥

`build/client.json` 和 `build/server.json` 是为了方便本地演示。真实部署时请重新生成自己的服务端密钥，并让每个客户端使用自己的私钥。

### 10. 停止后路由没有恢复怎么办

正常按 `Ctrl+C` 退出会触发清理逻辑。如果进程被强制杀掉，路由或 DNS 可能残留。可以重启网络适配器、重启系统，或手动删除指向 LwyV-Net TUN 网卡的分裂默认路由。

## 后续方向

短期适合继续做：

- Web 管理平台：在线节点、流量图表、租约列表、事件日志。
- 控制 API：踢客户端、释放租约、拉黑设备、热重载部分配置。
- Docker / systemd 部署模板。
- 更完整的 Windows 客户端体验。
- Android 配置页、扫码导入、日志页和 APK 分发。
- README 截图、部署视频和英文文档。

中长期方向：

- 多服务端节点管理。
- 中心控制面和节点注册。
- 客户端版本上报和自动更新。
- 只读 token / 管理 token / 操作审计。
- 设备分组、访问策略和权限系统。
- 更完整的安全审计和协议兼容策略。

## License

本项目使用 GNU Affero General Public License v3.0。详见 [LICENSE](./LICENSE)。
