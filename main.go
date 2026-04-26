package main

import (
	"NetworkSetup/vlan"
	"log"
	"os"
)

func main() {
	// 启动入口：
	// 1) 先读取 config.yaml 到全局变量 Conf。
	// 2) 没有传参时默认按客户端启动。
	// 3) 传参为 "server" 时按服务端启动。
	vlan.InitConfig("config.yaml")

	if len(os.Args) < 2 {
		// 默认模式：客户端
		vlan.StartClient()
		return
	}

	runType := os.Args[1]
	if runType == "server" {
		// 显式服务端模式：./程序名 server
		vlan.StartServer()
	} else {
		// 任何其它参数都视为非法，直接退出并给出提示。
		log.Fatal(runType + " is not a valid runType")
	}
}
