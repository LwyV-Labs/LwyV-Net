package vlan_net

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"
)

type ClientPeer struct {
	conn net.Conn
	mu   sync.Mutex
}
type KcpClient struct {
	sync.RWMutex
	m map[string]*ClientPeer
}

// 客户端路由表：key=虚拟IP，value=客户端连接对象
var clientKcpTable = &KcpClient{m: make(map[string]*ClientPeer)}

func StartServer() {
	if Conf.Common.Mode == "TCP" {
		startTCPServer()
	} else if Conf.Common.Mode == "KCP" {
		startKCPServer()
	} else if Conf.Common.Mode == "ALL" {
		go startTCPServer()
		startKCPServer()
	} else {
		log.Fatalf("{%s}不支持类型", Conf.Common.Mode)
	}
}

func startTCPServer() {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", Conf.Server.Port))
	if err != nil {
		log.Fatalf("服务端启动失败: %v", err)
	}
	defer listener.Close()

	log.Printf("✅ TCP 服务端启动成功，监听 :%d", Conf.Server.Port)
	log.Println("📝 等待客户端连接并转发IP包...")

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("接受连接失败: %v", err)
			continue
		}
		go handleClient(conn)
	}
}

func startKCPServer() {
	block, err := kcp.NewAESGCMCrypt(Conf.Common.Key)
	if err != nil {
		log.Fatalf("KCP AES-GCM 初始化失败: %v", err)
	}
	listener, err := kcp.ListenWithOptions(fmt.Sprintf(":%d", Conf.Server.Port), block, 0, 0)
	if err != nil {
		log.Fatalf("KCP服务端启动失败: %v", err)
	}
	defer listener.Close()

	log.Printf("✅ KCP 服务端启动成功，监听UDP :%d", Conf.Server.Port)
	log.Println("📝 等待客户端连接并转发IP包...")

	for {
		conn, err := listener.AcceptKCP()
		if err != nil {
			log.Printf("📝 接受连接失败: %v", err)
			continue
		}
		setupKCPSession(conn)
		go handleClient(conn)
	}
}

func handleClient(conn net.Conn) {
	peer := &ClientPeer{conn: conn}

	defer func() {
		clientKcpTable.Lock()
		for ip, p := range clientKcpTable.m {
			if p == peer {
				delete(clientKcpTable.m, ip)
				log.Printf("🗑️ 清理客户端路由: %s", ip)
			}
		}
		clientKcpTable.Unlock()

		err := conn.Close()
		if err != nil {
			log.Printf("🔌 客户端关闭失败")
			return
		}
		log.Printf("🔌 客户端已断开: %s", conn.RemoteAddr().String())
	}()

	log.Printf("🔌 新客户端连接: %s", conn.RemoteAddr().String())

	for {
		_ = conn.SetReadDeadline(time.Now().Add(readTimeout))

		pkt, err := readPacket(conn, Conf.Common.MTU)
		if err != nil {
			log.Printf("客户端断开连接: %s, 错误: %v", conn.RemoteAddr().String(), err)
			return
		}

		if string(pkt) == "PING" {
			peer.mu.Lock()
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			err := writePacket(conn, []byte("PONG"))
			peer.mu.Unlock()

			if err != nil {
				log.Printf("PONG发送失败: %v", err)
				return
			}
			continue
		}

		heardInfo, err := headerParsing(pkt)
		if err != nil {
			log.Printf("包头解析错误，丢弃：%v", err)
			continue
		}

		log.Printf("📥 收到IP包 | 类型:%s | 来源:%s | 目标:%s | 真实地址:%s | 大小:%d",
			heardInfo.ProtoName, heardInfo.SrcIP, heardInfo.DstIP, conn.RemoteAddr().String(), len(pkt))

		// 注册/刷新客户端虚拟IP映射
		clientKcpTable.Lock()
		clientKcpTable.m[heardInfo.SrcIP] = peer
		clientKcpTable.Unlock()

		// 广播/组播
		if heardInfo.IsBroadcast {
			broadcastPacket(&heardInfo, pkt)
			continue
		}

		// 单播
		clientKcpTable.RLock()
		targetPeer, exists := clientKcpTable.m[heardInfo.DstIP]
		clientKcpTable.RUnlock()

		if !exists {
			log.Printf("⚠️ 目标不存在: %s (未注册客户端)", heardInfo.DstIP)
			continue
		}

		targetPeer.mu.Lock()
		err = writePacket(targetPeer.conn, pkt)
		targetPeer.mu.Unlock()

		if err != nil {
			log.Printf("转发失败 [%s]: %v", heardInfo.DstIP, err)
			continue
		}

		log.Printf("✅ 成功转发至: %s", heardInfo.DstIP)
	}
}
