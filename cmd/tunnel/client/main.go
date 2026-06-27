// Command tunclient runs on the user's device (Windows/Android). It connects
// to a target NodeID over the P2P network, opens one tunnel connection, and
// listens on a local TCP port. Every local TCP connection is multiplexed as a
// sub-stream onto that single tunnel and forwarded to the server's web app.
//
// Usage:
//
//	tunclient -target <NodeID> [-index <addr>] [-listen <localAddr>]
//
// Then open http://<listen> in a browser (default http://127.0.0.1:15173).
package main

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"bnfs_p2p/cmd/tunnel/mux"
	"bnfs_p2p/logx"
	"bnfs_p2p/p2pnode"
	"bnfs_p2p/p2pnode/impl/natnode"
)

const defaultIndexAddr = "p2p.example.com:9000"

func main() {
	targetID := flag.String("target", "", "target server NodeID (64 hex chars)")
	indexAddr := flag.String("index", defaultIndexAddr, "index server address for bootstrap")
	relayAddr := flag.String("relay", "", "pin to a specific relay address (must match the server's relay)")
	listen := flag.String("listen", "", "local address to listen on (e.g. 127.0.0.1:8888)")
	keyFile := flag.String("key", "", "optional private key file")
	flag.Parse()

	// 交互式回退: 缺少监听地址或目标 NodeID 时, 提示用户输入。
	reader := bufio.NewReader(os.Stdin)

	if *listen == "" {
		fmt.Print("请输入本地监听端口 (如 8888, 回车默认 15173): ")
		line, _ := reader.ReadString('\n')
		line = strings.TrimSpace(line)
		if line == "" {
			*listen = "127.0.0.1:15173"
		} else if strings.Contains(line, ":") {
			*listen = line // 用户给了完整 host:port
		} else {
			*listen = "127.0.0.1:" + line // 只给了端口号
		}
	}

	if len(*targetID) != 64 {
		fmt.Print("请输入目标节点 NodeID (64 位 hex): ")
		line, _ := reader.ReadString('\n')
		*targetID = strings.TrimSpace(line)
	}

	if len(*targetID) != 64 {
		fmt.Printf("错误: NodeID 长度应为 64 位 hex, 实际 %d 位\n", len(*targetID))
		os.Exit(1)
	}

	logx.SetLevel(logx.LevelInfo)

	privKey, err := loadKey(*keyFile)
	if err != nil {
		log.Fatalf("加载私钥失败: %v", err)
	}

	bootstrapAddr := *indexAddr
	if *relayAddr != "" {
		bootstrapAddr = *relayAddr
	}
	node, err := natnode.NewNATNode(privKey, bootstrapAddr)
	if err != nil {
		log.Fatalf("创建节点失败: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Printf("=== Tunnel Client ===\n")
	fmt.Printf("本节点 ID: %s\n", node.ID())
	fmt.Printf("目标节点:  %s\n", *targetID)

	var entryRelay string
	if *relayAddr != "" {
		entryRelay = *relayAddr
		fmt.Printf("使用指定 relay: %s\n", entryRelay)
	} else {
		entryRelay, _ = node.Bootstrap(ctx, *indexAddr)
		fmt.Printf("注册到 relay: %s\n", entryRelay)
	}

	// A Listen loop is needed so the relay can route the return path.
	go func() {
		if err := node.Listen(ctx, entryRelay); err != nil {
			log.Printf("Listen 退出: %v", err)
		}
	}()

	// Connect with retries. Cross-relay routing in the P2P network can need a
	// few seconds (and retries) for DHT info to propagate, so a single failed
	// attempt is expected on first connect. Retry with backoff.
	fmt.Printf("正在连接目标节点 ...\n")
	var conn p2pnode.Connection
	for attempt := 1; ; attempt++ {
		c, err := node.Connect(ctx, p2pnode.NodeID(*targetID))
		if err == nil {
			conn = c
			break
		}
		if attempt >= 12 {
			log.Fatalf("连接目标失败（已重试 %d 次）: %v", attempt, err)
		}
		log.Printf("第 %d 次连接失败，3 秒后重试: %v", attempt, err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(3 * time.Second):
		}
	}
	fmt.Printf("已建立隧道连接。\n")

	sess := mux.NewSession(ctx, conn, true)
	defer sess.Close()

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatalf("监听 %s 失败: %v", *listen, err)
	}
	defer ln.Close()

	fmt.Printf("\n本地监听: %s\n", *listen)
	fmt.Printf("在浏览器打开: http://%s\n", *listen)
	fmt.Println("按 Ctrl+C 退出。")

	// If the session dies, stop accepting.
	go func() {
		<-sess.Context().Done()
		ln.Close()
	}()

	for {
		local, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-sess.Context().Done():
				log.Println("隧道已断开，退出。")
				return
			default:
				log.Printf("accept 错误: %v", err)
				continue
			}
		}
		go handleLocal(sess, local)
	}
}

// handleLocal opens a sub-stream on the tunnel for one local TCP connection
// and pipes bytes in both directions.
func handleLocal(sess *mux.Session, local net.Conn) {
	defer local.Close()

	stream, err := sess.OpenStream()
	if err != nil {
		log.Printf("打开子流失败: %v", err)
		return
	}
	defer stream.Close()

	pipe(stream, local)
}

func pipe(a io.ReadWriteCloser, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}

func loadKey(path string) (*ecdh.PrivateKey, error) {
	if path == "" {
		return nil, nil
	}
	if _, err := os.Stat(path); err == nil {
		return natnode.LoadPrivateKeyFromFile(path)
	}
	return natnode.LoadPrivateKeyFromHex(path)
}
