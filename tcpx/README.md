# LwyV-Net tcpx refactor v2

这个包把旧的 `securetcp` 底层替换为刚生成的 `tcpx`，并把上层拆成更清晰的几个边界：

- `tcpx/`：通用 TCP 加密传输库，负责帧、握手、AES-GCM、心跳、重连、换钥、抗重放。
- `vlan2/protocol.go`：vlan2 应用层帧，只保留 `TypeAuth / TypeVDHCP / TypeIP`。
- `vlan2/auth.go`：客户端长期身份认证。tcpx 只认证服务端公钥，这里再证明客户端持有自己的私钥。
- `vlan2/client.go`：客户端生命周期、TUN、tcpx 自动重连、DHCP 地址申请。
- `vlan2/server.go`：服务端生命周期、tcpx 回调、DHCP、IP 转发。
- `vlan2/peer.go`：服务端 peer 注册表和发送队列。
- `conf2/`：配置读取与校验，已移除旧 `secure` 包依赖。
- `vdhcp2/`：保留 JSON DHCP 消息，增强了租约管理和快照。

## 替换方式

把目录复制到你的项目根目录覆盖：

```text
conf2/
tcpx/
vdhcp2/
vlan2/
main.go
main_common.go
```

如果你的项目已有 `main.go`，可以只参考这个包里的入口程序，把 `genkey` 和监控逻辑合并过去。

## 配置兼容

原有配置仍然可用：

```json
{
  "privateKey": "base64-x25519-private-key",
  "serverPublicKey": "base64-x25519-public-key"
}
```

`privateKey` / `serverPublicKey` 支持：

- hex
- base64
- base64url

可选增加 `tcp` 配置来覆盖默认超时、心跳、换钥、重连参数：

```json
{
  "tcp": {
    "readTimeoutSeconds": 10,
    "writeTimeoutSeconds": 8,
    "heartbeatBaseSeconds": 4,
    "heartbeatJitterSeconds": 1,
    "keyRotateIntervalSeconds": 45,
    "oldKeyGraceSeconds": 20,
    "reconnectBaseSeconds": 1,
    "reconnectJitterSeconds": 3
  }
}
```

## 运行

```bash
go run . genkey
go run . server
go run . client
```

## 重要变化

旧代码中 `securetcp.Conn.PeerStaticPublicKeyB64()` 直接给服务端一个客户端身份。tcpx 的握手是服务端公钥认证，因此新版在加密通道内增加 `TypeAuth`：客户端发送自己的静态公钥和基于静态 ECDH 的 HMAC，服务端验证后把客户端静态公钥 hex 作为 `clientID`，继续用于 DHCP 租约、重连和流量统计。
