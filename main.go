package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/LwyV-Labs/LwyV-Net/vlan"
)

func main() {
	mode := parseRunMode(os.Args)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

	switch mode {
	case "genkey":
		vlan.Genkey()
		return
	case string(vlan.RunModeServer):
		server := vlan.NewServer()
		go server.Start()
		<-ch
		server.Stop()
		return
	case string(vlan.RunModeClient):
		client := vlan.NewClient()
		go client.Start()
		<-ch
		client.Stop()
		return
	}

}

func parseRunMode(args []string) string {
	// 启动入口：
	// 1) genkey 不启动客户端/服务端，只生成 Noise IK / ECDH 长期身份密钥并回写配置。
	// 2) 没有传参时默认按客户端启动。
	// 3) 支持 server / client 两种运行模式。
	if len(args) < 2 {
		return string(vlan.RunModeClient)
	}
	switch args[1] {
	case "genkey", string(vlan.RunModeServer), string(vlan.RunModeClient):
		return args[1]
	default:
		log.Fatalf("%s is not a valid runType", args[1])
		return ""
	}
}
