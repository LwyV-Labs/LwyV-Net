# securetcp

一个 Go TCP 安全传输库示例，包含：

- 固定帧头：`magic + version + frameType + length`
- magic/version 不匹配立即断开
- 循环读写指定长度，读写 deadline
- 客户端随机间隔 Ping，服务端自动 Pong
- X25519 + AES-GCM + HKDF 的 Noise-IK 风格握手
- 建立连接后所有业务数据和控制帧都加密认证
- AEAD 序号 + 滑动窗口抗重放
- 客户端自动重连，重用客户端/服务端长期身份密钥
- 客户端定时 rekey，旧密钥保留短暂 grace period 后过期
- gomobile wrapper，便于打包 AAR 给 Kotlin/Android 调用

> 说明：这里实现的是工程可用的“Noise-IK 风格”握手，不是 Noise Protocol Framework 的逐字节兼容实现。

## 快速运行

### 1. 生成服务端和客户端长期密钥

```bash
go run ./cmd/keygen
# 记下 SERVER_PRIVATE / SERVER_PUBLIC

go run ./cmd/keygen
# 记下 CLIENT_PRIVATE / CLIENT_PUBLIC
```

### 2. 启动服务端

```bash
go run ./cmd/server -addr :9443 -server-key "$SERVER_PRIVATE"
```

### 3. 启动客户端

```bash
go run ./cmd/client \
  -addr 127.0.0.1:9443 \
  -client-key "$CLIENT_PRIVATE" \
  -server-pub "$SERVER_PUBLIC" \
  -msg "hello" \
  -n 5
```

## Android / Kotlin AAR

安装 gomobile：

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init
```

打包：

```bash
gomobile bind -target=android -o securetcp.aar ./mobile
```

Kotlin 伪代码：

```kotlin
val c = mobile.Mobile.newClient(
    "1.2.3.4:9443",
    clientPrivateKeyB64,
    serverPublicKeyB64
)
c.connect()
c.send("hello".toByteArray())
val reply = c.recv()
c.close()
```

## 帧格式

| 字段 | 长度 | 说明 |
|---|---:|---|
| Magic | 4 bytes | 默认 `0x4c575954` |
| Version | 1 byte | 默认 `1` |
| FrameType | 1 byte | 握手、数据、心跳、rekey、关闭 |
| Length | 4 bytes | payload 长度，大端序 |

握手帧 payload 明文承载临时公钥和加密身份；握手完成后，Data/Ping/Pong/Rekey/Close 的 payload 都是 AES-GCM 密文，格式为：

```text
epoch(8) | seq(8) | ciphertext+tag
```

AEAD AAD 绑定了 `frameType + epoch + seq`，防止帧类型被替换。
