package main

import (
	"NetworkSetup/webui"
	"log"
	"os"
)

const configPath = "config.yaml"
const webConsoleAddr = ":52013"

func main() {
	// 启动入口（已简化）：
	// 1) web-client：客户端 Web 控制台
	// 2) web-server：服务端 Web 控制台
	if len(os.Args) >= 2 {
		runType := os.Args[1]
		switch runType {
		case "client":
			if err := webui.StartClientConsole(configPath, webConsoleAddr); err != nil {
				log.Fatalf("启动客户端 Web 控制台失败: %v", err)
			}
			return
		case "server":
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
