package main

import (
	"NetworkSetup/vlan"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

const configPath = "config.yaml"

func main() {
	mode := parseRunMode(os.Args)

	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

	switch mode {
	case "genkey":
		genkey()
		return
	case string(vlan.RunModeServer):
		vlan.InitConfig(configPath, vlan.RunModeServer)
		server := vlan.NewServer()
		server.Start()
		go func() {
			<-ch
			server.Cleanup()
			os.Exit(0)
		}()
		return
	case string(vlan.RunModeClient):
		vlan.InitConfig(configPath, vlan.RunModeClient)
		client := vlan.NewClient()
		client.Start()
		go func() {
			<-ch
			client.Cleanup()
			os.Exit(0)
		}()
		return
	}
	log.Fatal("unreachable")
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

func genkey() {
	// 用法：
	//   ./程序名 genkey
	//     生成本机 privateKey，写入 config.yaml，并打印本机 publicKey。
	peerPublicKey := ""
	if len(os.Args) >= 3 {
		peerPublicKey = os.Args[2]
	}
	publicKey, err := vlan.GenerateAndWriteKeys(configPath, peerPublicKey)
	if err != nil {
		log.Fatalf("生成并写入密钥失败: %v", err)
	}
	fmt.Println("✅ 已生成新的本机身份密钥，并写入", configPath)
	fmt.Println("本机 publicKey:", publicKey)
	fmt.Println("请把上面的 publicKey 填到对端 config.yaml 的 common.peerPublicKeys[0]")
	if peerPublicKey != "" {
		fmt.Println("✅ 已同时写入 common.peerPublicKeys[0]")
	}
}
