// hooktest 是 relayNode 转发 hook 功能的最小化验证程序。
//
// 验证目标（对应需求 2）：
//   relayNode 每转发帧累计到指定大小，就自动调用一次 hook；
//   hook 返回 nil 才继续转发；返回 error 则执行 errorHook（结构体参数传递）并停止该方向转发。
//
// 三种模式（脚本化三服务器部署，与 relaychat 一致）：
//
//	-mode relay   -listen :9000 [-public IP:9000] [-threshold 1048576] [-failat N]
//	    启动带转发 hook 的公网中继节点。
//	    -threshold  每累计转发多少字节触发一次 hook（默认 1MB）。
//	    -failat     第几次 hook 调用时返回 error 以触发 errorHook（默认 0=永不失败）。
//	    每次 hook 触发打印累计字节/帧数；errorHook 触发打印错误结构体内容。
//
//	-mode listen  -relay IP:9000
//	    NAT 节点（server 端），注册到 relay，回显收到的每条消息。打印自身 NodeID。
//
//	-mode connect -relay IP:9000 -target <NodeID> [-rounds 50] [-size 14336]
//	    NAT 节点（client 端），跨 relay 连接 target 并发送 -rounds 轮、每轮 -size 字节的数据，
//	    驱动 relay 转发足够字节以触发 hook。
//
// ── 三服务器拓扑（与需求一致）──
//
//	server1 (10.146.83.21) : relayServer
//	    hooktest -mode relay -listen 0.0.0.0:9000 -public 10.146.83.21:9000 -threshold 1048576
//	serverX (server 端) :
//	    hooktest -mode listen -relay 10.146.83.21:9000     # 记下打印的 NodeID
//	serverY (client 端) :
//	    hooktest -mode connect -relay 10.146.83.21:9000 -target <NodeID> -rounds 50 -size 14336
package main

import (
	"context"
	"crypto/ecdh"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"bnfs_p2p/crypoto"
	"bnfs_p2p/p2pnode"
	"bnfs_p2p/p2pnode/impl/natnode"
	"bnfs_p2p/p2pnode/impl/relaynode"
)

func main() {
	mode := flag.String("mode", "relay", "运行模式: relay | listen | connect")
	listen := flag.String("listen", ":9000", "relay 监听地址 (relay 模式)")
	public := flag.String("public", "", "relay 对外可达地址 (relay 模式, 默认同 listen)")
	relayAddr := flag.String("relay", "127.0.0.1:9000", "要注册到的 relay 地址 (listen/connect 模式)")
	target := flag.String("target", "", "目标 NodeID (connect 模式)")
	rounds := flag.Int("rounds", 50, "通信轮数 (connect 模式)")
	size := flag.Int("size", 14336, "每轮消息字节数 (connect 模式)")
	threshold := flag.Int64("threshold", 1<<20, "hook 触发的字节阈值 (relay 模式)")
	failAt := flag.Int("failat", 0, "第几次 hook 调用返回 error (relay 模式, 0=永不失败)")
	flag.Parse()

	switch *mode {
	case "relay":
		runRelay(*listen, *public, *threshold, *failAt)
	case "listen":
		runListen(*relayAddr)
	case "connect":
		runConnect(*relayAddr, *target, *rounds, *size)
	default:
		fmt.Printf("未知模式: %s\n", *mode)
		os.Exit(1)
	}
}

// runRelay 启动带转发 hook 的中继节点。
func runRelay(listen, public string, threshold int64, failAt int) {
	privKey, err := crypoto.MakeKeyPair()
	if err != nil {
		log.Fatalf("生成私钥失败: %v", err)
	}
	var _ *ecdh.PrivateKey = privKey

	rn, err := relaynode.NewRelayNode(privKey, listen, public)
	if err != nil {
		log.Fatalf("创建 relay 节点失败: %v", err)
	}

	// hookCallCount 记录 hook 被调用的总次数；用于 -failat 决定第几次返回 error。
	var hookCallCount atomic.Int64
	var totalForwarded atomic.Int64

	// 配置转发 hook：每累计 threshold 字节调用一次。
	rn.SetForwardHook(&relaynode.ForwardHookConfig{
		ThresholdBytes: threshold,
		Hook: func(ctx context.Context, stats *relaynode.ForwardStats) error {
			n := hookCallCount.Add(1)
			total := totalForwarded.Add(stats.TotalBytes)
			fmt.Printf("[HOOK #%d] 本次累计转发 %d 字节 / %d 帧, 累计总转发 %d 字节\n",
				n, stats.TotalBytes, stats.TotalFrames, total)

			// 模拟业务校验失败：第 failAt 次调用返回 error，触发 errorHook。
			if failAt > 0 && int(n) == failAt {
				return fmt.Errorf("模拟业务拒绝: 第%d次hook主动返回error(已转发%d字节)", n, total)
			}
			return nil
		},
		// errorHook 用结构体参数传递错误上下文。
		ErrorHook: func(ctx context.Context, info *relaynode.ForwardErrorInfo) {
			fmt.Printf("[ERROR-HOOK] 转发被终止!\n")
			fmt.Printf("    方向(Direction): %s\n", info.Direction)
			fmt.Printf("    错误(Err): %v\n", info.Err)
			if info.Stats != nil {
				fmt.Printf("    触发时统计(Stats): 字节=%d 帧数=%d\n",
					info.Stats.TotalBytes, info.Stats.TotalFrames)
			}
		},
	})

	fmt.Printf("RelayNode ID: %s\n", rn.ID())
	fmt.Printf("监听: %s  对外地址: %s\n", listen, rn.Addr())
	fmt.Printf("转发 hook 已启用: 阈值=%d 字节, 失败点=%d\n", threshold, failAt)

	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			hosted := rn.HostedNatNodesDetailed()
			fmt.Printf("[状态] 托管NAT节点=%d, hook调用次数=%d, 累计转发=%d字节\n",
				len(hosted), hookCallCount.Load(), totalForwarded.Load())
		}
	}()

	rn.Start() // 阻塞
}

// runListen 启动 server 端 NAT 节点，回显收到的消息。
func runListen(relayAddr string) {
	privKey, err := crypoto.MakeKeyPair()
	if err != nil {
		log.Fatalf("生成私钥失败: %v", err)
	}
	node, err := natnode.NewNATNode(privKey, relayAddr)
	if err != nil {
		log.Fatalf("创建节点失败: %v", err)
	}
	defer node.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var recvCount atomic.Int64
	node.OnConnection(func(conn p2pnode.Connection) {
		fmt.Printf("[入站连接] 来自 %s\n", conn.Peer().ID)
		go func() {
			for {
				recv, err := conn.Receive(ctx)
				if err != nil {
					fmt.Printf("[断开] %s: %v\n", conn.Peer().ID, err)
					return
				}
				n := recvCount.Add(1)
				if n%10 == 0 {
					fmt.Printf("[收到第%d条] %d 字节\n", n, len(recv.Payload))
				}
				reply := &p2pnode.Message{Type: p2pnode.MsgAppData, Payload: recv.Payload}
				if err := conn.Send(ctx, reply); err != nil {
					fmt.Printf("[回显失败] %s: %v\n", conn.Peer().ID, err)
					return
				}
			}
		}()
	})

	fmt.Printf("NAT 节点 ID: %s\n", node.ID())
	fmt.Printf("注册到 relay: %s\n", relayAddr)
	fmt.Println("等待入站连接, 回显收到的每条消息 ...")

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

// runConnect 启动 client 端 NAT 节点，跨 relay 连接 target 并发送多轮数据。
func runConnect(relayAddr, target string, rounds, size int) {
	if len(target) != 64 {
		log.Fatalf("无效的 target NodeID 长度: %d (应为64位hex)", len(target))
	}
	privKey, err := crypoto.MakeKeyPair()
	if err != nil {
		log.Fatalf("生成私钥失败: %v", err)
	}
	node, err := natnode.NewNATNode(privKey, relayAddr)
	if err != nil {
		log.Fatalf("创建节点失败: %v", err)
	}
	defer node.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = node.Listen(ctx, relayAddr) }()

	fmt.Printf("NAT 节点 ID: %s\n", node.ID())
	fmt.Printf("注册到 relay: %s\n", relayAddr)
	time.Sleep(1 * time.Second)

	fmt.Printf("正在跨中继连接 target %s ...\n", target)
	connCtx, connCancel := context.WithTimeout(ctx, 15*time.Second)
	defer connCancel()
	conn, err := node.Connect(connCtx, p2pnode.NodeID(target))
	if err != nil {
		log.Fatalf("连接失败: %v", err)
	}
	fmt.Printf("已连接到 %s, 开始 %d 轮通信 (每轮 %d 字节)\n", target, rounds, size)

	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	ok := 0
	for i := 0; i < rounds; i++ {
		if err := conn.Send(ctx, &p2pnode.Message{Type: p2pnode.MsgAppData, Payload: payload}); err != nil {
			fmt.Printf("第 %d 轮发送失败: %v\n", i, err)
			break
		}
		recvCtx, recvCancel := context.WithTimeout(ctx, 10*time.Second)
		_, err := conn.Receive(recvCtx)
		recvCancel()
		if err != nil {
			fmt.Printf("第 %d 轮接收失败: %v\n", i, err)
			break
		}
		ok++
		if (i+1)%10 == 0 {
			fmt.Printf("→ 已完成 %d/%d 轮\n", i+1, rounds)
		}
	}
	fmt.Printf("通信完成: 成功 %d/%d 轮, 共发送约 %d 字节\n", ok, rounds, ok*size)
	if ok != rounds {
		os.Exit(1)
	}
}
