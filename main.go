package main

import (
	"NetworkSetup/vlan"
	"fmt"
	"log"
	"os"
)

const configPath = "config.yaml"

func main() {
	// 启动入口：
	// 1) genkey 不启动客户端/服务端，只生成 Noise IK / ECDH 长期身份密钥并回写配置。
	// 2) setpeer 只写入对端长期公钥，不改变本机 privateKey。
	// 3) 没有传参时默认按客户端启动。
	// 4) 传参为 "server" 时按服务端启动；传参为 "client" 时按客户端启动。
	if len(os.Args) >= 2 {
		runType := os.Args[1]
		switch runType {
		case "genkey":
			// 用法：
			//   ./程序名 genkey
			//     生成本机 privateKey，写入 config.yaml，并打印本机 publicKey。
			//
			//   ./程序名 genkey <peerPublicKey>
			//     生成本机 privateKey，同时把传入的对端长期公钥写入 common.peerPublicKey。
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
			fmt.Println("请把上面的 publicKey 填到对端 config.yaml 的 common.peerPublicKey")
			if peerPublicKey != "" {
				fmt.Println("✅ 已同时写入 common.peerPublicKey")
			}
			return
		case "setpeer":
			// 用法：
			//   ./程序名 setpeer <peerPublicKey>
			//     只写入 common.peerPublicKey，不重新生成本机 privateKey。
			if len(os.Args) < 3 {
				log.Fatal("用法: 程序名 setpeer <peerPublicKey>")
			}
			if err := vlan.WritePeerPublicKey(configPath, os.Args[2]); err != nil {
				log.Fatalf("写入peerPublicKey失败: %v", err)
			}
			fmt.Println("✅ 已写入 common.peerPublicKey，不会改变本机 privateKey")
			return
		case "server":
			vlan.InitConfig(configPath)
			vlan.StartServer()
			return
		case "client":
			vlan.InitConfig(configPath)
			vlan.StartClient()
			return
		default:
			log.Fatal(runType + " is not a valid runType")
		}
	}

	// 默认模式：客户端
	vlan.InitConfig(configPath)
	vlan.StartClient()
}
