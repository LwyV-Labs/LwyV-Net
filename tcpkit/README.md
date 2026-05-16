# tcpkit

一个轻量级 Go TCP 封装库，内置固定帧协议、客户端/服务端、心跳、读写超时、定长读写，并尽量保持 Android/Kotlin gomobile 绑定友好。

## 帧格式

固定 10 字节头部，全部使用 Big Endian：

```text
uint32 magic          // 4 bytes，默认 ASCII "TKIT"，0x544B4954
uint8  version        // 1 byte，默认 1
uint8  frame_type     // 1 byte
uint32 payload_length // 4 bytes
payload               // payload_length bytes
```

## 帧类型

```go
const (
    FrameTypeData  int32 = 1
    FrameTypePing  int32 = 2
    FrameTypePong  int32 = 3
    FrameTypeClose int32 = 4
)
```

## 事件类型

```go
const (
    EventOpen  int32 = 1
    EventData  int32 = 2
    EventFrame int32 = 3
    EventClose int32 = 4
    EventError int32 = 5
)
```

## 主要特性

- 客户端连接成功后自动定时 Ping
- 服务端收到 Ping 自动 Pong
- 客户端和服务端都能自动回复 Pong
- 可配置心跳间隔
- 可配置读超时和写超时
- 内部使用严格定长读取 `readExact`
- 内部使用严格完整写入 `writeExact`
- 支持最大 payload 限制，防止恶意长度撑爆内存
- 回调接口单一，方便 Android/Kotlin 调用
- `Start`、`Send`、`Stop` 返回 string，空字符串表示成功，便于 gomobile 映射

## 服务端示例

```go
package main

import (
    "fmt"
    "github.com/gotoandy203/tcpkit"
)

type myHandler struct{}

func (myHandler) OnEvent(e *tcpkit.Event) {
    switch e.GetType() {
    case tcpkit.EventOpen:
        fmt.Println("open:", e.GetConnection().GetRemoteAddr())
    case tcpkit.EventData:
        fmt.Println("data:", string(e.GetPayload()))
        e.GetConnection().SendText("server received")
    case tcpkit.EventClose:
        fmt.Println("close:", e.GetMessage())
    case tcpkit.EventError:
        fmt.Println("error:", e.GetMessage())
    }
}

func main() {
    cfg := tcpkit.NewConfig()
    cfg.HeartbeatIntervalMillis = 15000
    cfg.ReadTimeoutMillis = 45000
    cfg.WriteTimeoutMillis = 10000

    server := tcpkit.NewServer(":9000", cfg, myHandler{})
    if err := server.StartBlocking(); err != "" {
        panic(err)
    }
}
```

## 客户端示例

```go
package main

import (
    "fmt"
    "github.com/gotoandy203/tcpkit"
)

type myHandler struct{}

func (myHandler) OnEvent(e *tcpkit.Event) {
    switch e.GetType() {
    case tcpkit.EventOpen:
        fmt.Println("connected")
    case tcpkit.EventData:
        fmt.Println("server:", string(e.GetPayload()))
    case tcpkit.EventError:
        fmt.Println("error:", e.GetMessage())
    }
}

func main() {
    cfg := tcpkit.NewConfig()

    client := tcpkit.NewClient("127.0.0.1:9000", cfg, myHandler{})
    if err := client.Start(); err != "" {
        panic(err)
    }

    client.SendText("hello")
    select {}
}
```

## 配置说明

```go
cfg := tcpkit.NewConfig()
cfg.Magic = 0x544B4954
cfg.Version = 1
cfg.MaxPayloadBytes = 4 * 1024 * 1024
cfg.ReadTimeoutMillis = 45000
cfg.WriteTimeoutMillis = 10000
cfg.HeartbeatIntervalMillis = 15000
cfg.ServerAutoPing = false
cfg.NotifyHeartbeat = false
```

建议：`ReadTimeoutMillis` 至少设置成 `HeartbeatIntervalMillis` 的 2 到 3 倍。比如心跳 15 秒，读超时可以设置 45 秒。

## 运行示例

先启动服务端：

```bash
go run ./examples/server
```

再启动客户端：

```bash
go run ./examples/client
```

## Android / Kotlin

见：`android/README_ANDROID.md`

核心命令：

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
gomobile init

gomobile bind \
  -target=android/arm64 \
  -javapkg=com.gotandy.tcpkit \
  -o tcpkit.aar \
  github.com/gotoandy203/tcpkit
```

## 注意事项

1. 这是帧协议库，不是加密协议。需要加密可以在 payload 层加 AEAD，或者在 TCP 外层使用 TLS。
2. TCP 是流协议，不能假设一次 Read 就是一包，所以本库用固定头部 + payload_length + 定长读取解决粘包/半包问题。
3. Handler 回调可能来自 Go goroutine。Android 更新 UI 时要切回主线程。
4. 多 goroutine 同时 Send 是安全的，内部有写锁。
