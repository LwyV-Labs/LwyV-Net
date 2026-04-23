# dev-v0.03版

### 1.实现TCP，KCP双协议
### 2.优化重连机制


# dev-v0.02版

### 1.增加断线重连机制
### 2.密钥加密
### 3.优化代码结构降低延迟

# dev-v0.01版
### 1.初始可用版本


# 工作原理
应用程序
↓
Windows 协议栈
↓
TUN 虚拟网卡
↓
Go 读取 TUN
↓
writePacket 封包
↓
TCP / KCP
↓
服务端转发
↓
对端 TCP / KCP
↓
Go 写入 TUN
↓
对端 Windows 协议栈
↓
对端应用程序



##========================================================================
##
chmod +x vlan.bin
### 启动运行
sudo ./vlan.bin server
./vlan 


### 关闭防火墙
netsh advfirewall set allprofiles state off


### 打包
go build -o build/vlan.exe

$env:CGO_ENABLED=0; $env:GOOS="linux"; $env:GOARCH="amd64"; go build -o build/vlan.bin

sudo nohup ./vlan.bin server &>/dev/null &

sudo nohup ./vlan.bin server > server.log 2>&1 &

sudo while true; do ./vlan server; sleep 1; done

ps -ef | grep vlan.bin

kill -9 进程ID

kill 进程ID