package main

import (
	"NetworkSetup/vlan"
	"NetworkSetup/webui"
	"fmt"
	"log"
	"os"
)

const configPath = "config.yaml"
const webConsoleAddr = ":8080"

func main() {
	// 启动入口：
	// 1) genkey 不启动客户端/服务端，只生成 Noise IK / ECDH 长期身份密钥并回写配置。
	// 2) 没有传参时默认按客户端启动。
	// 3) 传参为 "server" 时按服务端启动；传参为 "client" 时按客户端启动。
	if len(os.Args) >= 2 {
		runType := os.Args[1]
		switch runType {
		case "genkey":
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
			return
		case "server":
			vlan.InitConfig(configPath, vlan.RunModeServer)
			vlan.StartServer()
			return
		case "client":
			vlan.InitConfig(configPath, vlan.RunModeClient)
			vlan.StartClient()
			return
		case "web-client":
			if err := webui.StartClientConsole(configPath, webConsoleAddr); err != nil {
				log.Fatalf("启动客户端 Web 控制台失败: %v", err)
			}
			return
		case "web-server":
			if err := webui.StartServerConsole(configPath, webConsoleAddr); err != nil {
				log.Fatalf("启动服务端 Web 控制台失败: %v", err)
			}
			return
		default:
			log.Fatal(runType + " is not a valid runType")
		}
	}

	// 默认模式：web-client
	if err := webui.StartClientConsole(configPath, webConsoleAddr); err != nil {
		log.Fatalf("启动客户端 Web 控制台失败: %v", err)
	}
}
