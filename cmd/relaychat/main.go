// relaychat 是 relayNode 跨中继能力的验证程序（参考 cmd/p2pchat/main.go）。
//
// 三种模式（flag 驱动, 便于脚本化双服务器部署）：
//
//	-mode relay  -listen :9000 [-public IP:9000] [-peer IP2:9000] [-key file]
//	    启动一个公网中继节点。-peer 指定要主动建立控制链路的对端 relay 地址（可多次, 逗号分隔）。
//
//	-mode listen -relay IP:9000 [-key file]
//	    启动一个 NAT 节点, 注册到 relay 并对收到的每条消息回显 "echo:<原文>"。
//	    启动后打印自身 NodeID（供 connect 方使用）。
//
//	-mode connect -relay IP:9000 -target <NodeID> [-rounds 3] [-msg hello]
//	    启动一个 NAT 节点, 注册到 relay, 连接 target 节点并发起 N 轮请求/响应通信。
//
// 也支持 -mode interactive 进入交互式控制台（行为接近 p2pchat）。
package main

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"bnfs_p2p/p2pnode"
	"bnfs_p2p/p2pnode/impl/natnode"
	"bnfs_p2p/p2pnode/impl/relaynode"
)

func main() {
	mode := flag.String("mode", "interactive", "运行模式: relay | listen | connect | interactive")
	listen := flag.String("listen", ":9000", "relay 监听地址 (relay 模式)")
	public := flag.String("public", "", "relay 对外可达地址 (relay 模式, 默认同 listen)")
	peer := flag.String("peer", "", "要建立控制链路的对端 relay 地址, 逗号分隔 (relay 模式)")
	relayAddr := flag.String("relay", "127.0.0.1:9000", "要注册到的 relay 地址 (listen/connect 模式)")
	target := flag.String("target", "", "目标 NodeID (connect 模式)")
	rounds := flag.Int("rounds", 3, "通信轮数 (connect 模式)")
	msg := flag.String("msg", "hello", "每轮消息前缀 (connect 模式)")
	keyFile := flag.String("key", "", "私钥文件, 用同一身份再次上线")
	flag.Parse()

	switch *mode {
	case "relay":
		runRelay(*listen, *public, *peer, *keyFile)
	case "listen":
		runListen(*relayAddr, *keyFile)
	case "connect":
		runConnect(*relayAddr, *target, *rounds, *msg, *keyFile)
	case "interactive":
		runInteractive()
	default:
		fmt.Printf("未知模式: %s\n", *mode)
		os.Exit(1)
	}
}

func loadKey(path string) (*ecdh.PrivateKey, error) {
	if path == "" {
		return nil, nil
	}
	if _, statErr := os.Stat(path); statErr == nil {
		return natnode.LoadPrivateKeyFromFile(path)
	}
	return natnode.LoadPrivateKeyFromHex(path)
}

// runRelay 启动一个公网中继节点并维持到各对端 relay 的控制链路（阻塞）。
func runRelay(listen, public, peer, keyFile string) {
	privKey, err := loadKey(keyFile)
	if err != nil {
		fmt.Printf("加载私钥失败: %v\n", err)
		os.Exit(1)
	}
	rn, err := relaynode.NewRelayNode(privKey, listen, public)
	if err != nil {
		fmt.Printf("创建 relay 节点失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("RelayNode ID: %s\n", rn.ID())
	fmt.Printf("监听: %s  对外地址: %s\n", listen, rn.Addr())

	if peer != "" {
		for _, addr := range strings.Split(peer, ",") {
			addr = strings.TrimSpace(addr)
			if addr == "" {
				continue
			}
			rn.ConnectPeer(addr)
			fmt.Printf("维持到对端 relay 的控制链路: %s\n", addr)
		}
	}

	// 周期性打印路由表状态, 便于观察 DHT 区分与托管情况。
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			fmt.Printf("[状态] relay邻居=%d 托管NAT节点=%d\n",
				len(rn.RelayNeighbors()), len(rn.HostedNatNodes()))
		}
	}()

	rn.Start() // 阻塞
}

// runListen 启动一个 NAT 节点, 注册到 relay, 对每条消息回显。
func runListen(relayAddr, keyFile string) {
	privKey, err := loadKey(keyFile)
	if err != nil {
		fmt.Printf("加载私钥失败: %v\n", err)
		os.Exit(1)
	}
	node, err := natnode.NewNATNode(privKey, relayAddr)
	if err != nil {
		fmt.Printf("创建节点失败: %v\n", err)
		os.Exit(1)
	}
	defer node.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	node.OnConnection(func(conn p2pnode.Connection) {
		fmt.Printf("[入站连接] 来自 %s\n", conn.Peer().ID)
		go echoLoop(ctx, conn)
	})

	fmt.Printf("NAT 节点 ID: %s\n", node.ID())
	fmt.Printf("注册到 relay: %s\n", relayAddr)
	fmt.Println("等待入站连接, 将对每条消息回显 echo:<原文> ...")

	// 注意：natnode.Listen 在首个入站连接被消费后即返回（注册流被复用为该连接）,
	// 但我们要持续为已建立的连接服务（echoLoop 在 OnConnection 回调里运行）, 因此 Listen 返回后
	// 不能退出 runListen（否则 defer node.Close()/cancel 会关掉连接）。这里阻塞直到收到中断信号。
	go func() {
		if err := node.Listen(ctx, relayAddr); err != nil {
			fmt.Printf("Listen 退出: %v\n", err)
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh
	fmt.Println("\n收到中断信号, 退出")
}

func echoLoop(ctx context.Context, conn p2pnode.Connection) {
	for {
		recv, err := conn.Receive(ctx)
		if err != nil {
			fmt.Printf("[断开] %s: %v\n", conn.Peer().ID, err)
			return
		}
		text := string(recv.Payload)
		fmt.Printf("[收到] %s: %s\n", conn.Peer().ID, text)
		reply := &p2pnode.Message{Type: p2pnode.MsgAppData, Payload: []byte("echo:" + text)}
		if err := conn.Send(ctx, reply); err != nil {
			fmt.Printf("[回显失败] %s: %v\n", conn.Peer().ID, err)
			return
		}
	}
}

// runConnect 启动一个 NAT 节点, 注册到 relay, 连接 target 并发起 N 轮请求/响应通信。
func runConnect(relayAddr, target string, rounds int, msgPrefix, keyFile string) {
	if len(target) != 64 {
		fmt.Printf("无效的 target NodeID 长度: %d (应为64位hex)\n", len(target))
		os.Exit(1)
	}
	privKey, err := loadKey(keyFile)
	if err != nil {
		fmt.Printf("加载私钥失败: %v\n", err)
		os.Exit(1)
	}
	node, err := natnode.NewNATNode(privKey, relayAddr)
	if err != nil {
		fmt.Printf("创建节点失败: %v\n", err)
		os.Exit(1)
	}
	defer node.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// 必须启动 Listen：注册本节点到 relay 并运行节点连接机制（与进程内测试一致）。
	go func() { _ = node.Listen(ctx, relayAddr) }()

	fmt.Printf("NAT 节点 ID: %s\n", node.ID())
	fmt.Printf("注册到 relay: %s\n", relayAddr)
	time.Sleep(1 * time.Second)

	fmt.Printf("正在跨中继连接 target %s ...\n", target)
	connCtx, connCancel := context.WithTimeout(ctx, 15*time.Second)
	defer connCancel()
	conn, err := node.Connect(connCtx, p2pnode.NodeID(target))
	if err != nil {
		fmt.Printf("连接失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("已连接到 %s, 开始 %d 轮通信\n", target, rounds)

	ok := 0
	for i := 0; i < rounds; i++ {
		out := fmt.Sprintf("%s-%d", msgPrefix, i)
		if err := conn.Send(ctx, &p2pnode.Message{Type: p2pnode.MsgAppData, Payload: []byte(out)}); err != nil {
			fmt.Printf("第 %d 轮发送失败: %v\n", i, err)
			break
		}
		fmt.Printf("→ 第 %d 轮 发送: %s\n", i, out)
		recvCtx, recvCancel := context.WithTimeout(ctx, 10*time.Second)
		recv, err := conn.Receive(recvCtx)
		recvCancel()
		if err != nil {
			fmt.Printf("第 %d 轮接收失败: %v\n", i, err)
			break
		}
		fmt.Printf("← 第 %d 轮 收到: %s\n", i, string(recv.Payload))
		ok++
	}
	fmt.Printf("通信完成: 成功 %d/%d 轮\n", ok, rounds)
	if ok != rounds {
		os.Exit(1)
	}
}

// runInteractive 进入交互式控制台。
func runInteractive() {
	fmt.Println("=== relaychat 交互模式 ===")
	fmt.Println("用法:")
	fmt.Println("  relay <listen> [peer]   启动中继节点, 可选与对端 relay 建链")
	fmt.Println("  node  <relayAddr>       启动 NAT 节点 (回显模式)")
	fmt.Println("  quit                    退出")
	scanner := bufio.NewScanner(os.Stdin)
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			return
		}
		fields := strings.Fields(strings.TrimSpace(scanner.Text()))
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "quit":
			return
		case "relay":
			listen := ":9000"
			if len(fields) > 1 {
				listen = fields[1]
			}
			peer := ""
			if len(fields) > 2 {
				peer = fields[2]
			}
			runRelay(listen, "", peer, "")
		case "node":
			addr := "127.0.0.1:9000"
			if len(fields) > 1 {
				addr = fields[1]
			}
			runListen(addr, "")
		default:
			fmt.Printf("未知命令: %s\n", fields[0])
		}
	}
}
