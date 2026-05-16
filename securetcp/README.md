# securetcp

一个可打包成库的 Go TCP 安全帧协议骨架，适合继续扩展成 Android/Kotlin 可调用的网络 SDK。

## 协议帧

固定 8 字节头：

| 字段 | 大小 | 说明 |
|---|---:|---|
| Magic | 2 | 默认 `0x4c56` |
| Version | 1 | 当前 `1` |
| FrameType | 1 | 帧类型 |
| Length | 4 | BigEndian，payload 长度 |

握手完成后，除握手帧外，`DATA / PING / PONG / CLOSE / REKEY` 的 payload 都会使用 AES-256-GCM 加密认证。

## 已实现能力

- 服务端 / 客户端两部分
- 固定帧头 + 指定长度循环读写
- 心跳：客户端和服务端都会按间隔发送 PING，收到 PING 自动 PONG
- 读写超时
- X25519 + AES-GCM + HKDF 的 Noise-IK 风格握手
- 客户端预置服务端公钥，连接后自动加密
- 定时自动 rekey，旧密钥有 grace 过期时间
- session ticket 恢复：断线重连可复用上一次会话票据派生新密钥
- 客户端非主动断开后可自动重连
- gomobile 友好的 `MobileClient` 包装

## 最小服务端

```go
serverKP, _ := securetcp.GenerateKeyPair()

srv, err := securetcp.Listen(":9000", securetcp.Config{
    ServerStaticPrivateKey: serverKP.Private,
    AllowResume: true,
}, func(c *securetcp.Conn) {
    for {
        msg, err := c.ReadMessage()
        if err != nil {
            return
        }
        _ = c.WriteMessage(msg)
    }
})
if err != nil { panic(err) }
defer srv.Close()

fmt.Printf("server public key: %x\n", serverKP.Public)
```

## 最小客户端

```go
client, err := securetcp.NewClient("127.0.0.1:9000", securetcp.Config{
    ServerStaticPublicKey: serverPublicKey,
    AllowResume: true,
    AutoReconnect: true,
})
if err != nil { panic(err) }

conn, err := client.Connect(context.Background())
if err != nil { panic(err) }
defer conn.Close()

_ = conn.WriteMessage([]byte("hello"))
reply, _ := conn.ReadMessage()
fmt.Println(string(reply))
```

## Android/Kotlin 方向

`MobileClient` 避免把 Go channel 直接暴露给 Kotlin：

```go
mc, err := securetcp.NewMobileClient("1.2.3.4:9000", serverPublicKey, nil)
_ = mc.Start()
_ = mc.Write([]byte("hello"))
msg, err := mc.Read(3000)
```

后续用 gomobile 绑定时，可以把该包编译成 Android AAR，然后 Kotlin 调用 `NewMobileClient / Start / Stop / Write / Read / IsConnected / LastError`。

## 重要说明

这个实现是“Noise IK 思路”的轻量实现，不是逐字节兼容 Noise Protocol Framework 的标准消息格式。它的目标是工程可用、无第三方依赖、便于打包给 Android。若要做正式商用协议，建议继续增加：协议版本协商、服务端对客户端公钥白名单、限流、握手失败日志、fuzz 测试、抗重放窗口、完整安全审计。
