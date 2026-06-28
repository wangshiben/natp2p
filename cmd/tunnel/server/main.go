// Command tunserver runs on the machine hosting the web app. It registers a
// NAT node via the index server, accepts inbound tunnel connections from
// clients, and forwards every multiplexed sub-stream to a local TCP address
// (the web server, e.g. 127.0.0.1:5173).
//
// Usage:
//
//	tunserver [-index <addr>] [-target <localAddr>] [-key <keyFile>]
//
// It prints its NodeID on startup; clients connect using that ID.
package main

import (
	"context"
	"crypto/ecdh"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"bnfs_p2p/cmd/tunnel/mux"
	"bnfs_p2p/logx"
	"bnfs_p2p/p2pnode"
	"bnfs_p2p/p2pnode/impl/natnode"
)

const defaultIndexAddr = "p2p.example.com:9000"

func main() {
	indexAddr := flag.String("index", defaultIndexAddr, "index server address for bootstrap")
	relayAddr := flag.String("relay", "", "pin to a specific relay address (skip auto-select); use the same value on client")
	target := flag.String("target", "127.0.0.1:5173", "local TCP address to forward traffic to")
	keyFile := flag.String("key", "", "optional private key file to keep a stable NodeID")
	flag.Parse()

	logx.SetLevel(logx.LevelInfo)

	privKey, err := loadKey(*keyFile)
	if err != nil {
		log.Fatalf("加载私钥失败: %v", err)
	}

	// If a relay is pinned, use it as the bootstrap relay so it becomes this
	// node's sole entry relay (NewNATNode registers bootstrapRelay in
	// entryRelays, and NAT nodes only dial via their own entry relay).
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

	// Each inbound P2P connection becomes a tunnel session.
	node.OnConnection(func(conn p2pnode.Connection) {
		peer := conn.Peer()
		fmt.Printf("[隧道] 客户端 %s 已连接\n", peer.ID)
		go handleTunnel(ctx, conn, *target)
	})

	fmt.Printf("=== Tunnel Server ===\n")
	fmt.Printf("本节点 ID: %s\n", node.ID())
	fmt.Printf("转发目标: %s\n", *target)

	// Entry relay selection. By default Bootstrap auto-picks a relay by XOR
	// distance from this node's ID, which means server and client can land on
	// different relays. If cross-relay bridging is unreliable, pin both ends to
	// the same relay with -relay.
	var entryRelay string
	if *relayAddr != "" {
		entryRelay = *relayAddr
		fmt.Printf("使用指定 relay: %s\n", entryRelay)
	} else {
		entryRelay, _ = node.Bootstrap(ctx, *indexAddr)
		fmt.Printf("注册到 relay: %s\n", entryRelay)
		fmt.Printf("提示: 若客户端连接失败，请让客户端用 -relay %s 固定到同一 relay\n", entryRelay)
	}

	// natnode.Listen blocks until the first inbound connection is consumed
	// (its registration stream is reused for that connection), then returns;
	// the connection keeps being served by the OnConnection callback. We must
	// NOT re-call Listen while a connection is active — it would contend for
	// the same registration stream and corrupt frames. One tunnel per server.
	go func() {
		if err := node.Listen(ctx, entryRelay); err != nil {
			if ctx.Err() == nil {
				log.Printf("Listen 退出: %v", err)
			}
		}
	}()

	fmt.Println("\n服务端已就绪，等待客户端连接。客户端使用上面的 NodeID 连接。")
	fmt.Println("按 Ctrl+C 退出。")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("\n正在关闭...")
	cancel()
	node.Close()
}

// handleTunnel runs a mux session over one inbound P2P connection. For each
// sub-stream opened by the client, it dials the local target and pipes bytes.
func handleTunnel(ctx context.Context, conn p2pnode.Connection, target string) {
	sess := mux.NewSession(ctx, conn, false)
	defer sess.Close()

	for {
		stream, err := sess.Accept()
		if err != nil {
			return
		}
		go forwardToLocal(stream, target)
	}
}

// forwardToLocal dials the local TCP target and pipes both directions.
func forwardToLocal(stream *mux.Stream, target string) {
	defer stream.Close()

	local, err := net.Dial("tcp", target)
	if err != nil {
		log.Printf("拨号本地 %s 失败: %v", target, err)
		return
	}
	defer local.Close()

	pipe(stream, local)
}

// pipe copies bytes in both directions until either side closes.
// 用大缓冲 io.CopyBuffer 而非裸 io.Copy(32KB)：裸 Copy 每次最多喂 32KB 给 mux.Write，
// 会把单条消息钉死在 32KB，跨境高 RTT 下吞吐受限于 32KB/RTT。大缓冲让一次 Read 能拿到
// 更多字节、合成更大的单条 mux 消息（一个 ACK 往返摊更多字节）。缓冲大小经 pumpBufSize 配置。
func pipe(a io.ReadWriteCloser, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() { io.CopyBuffer(a, b, make([]byte, pumpBufSize())); done <- struct{}{} }()
	go func() { io.CopyBuffer(b, a, make([]byte, pumpBufSize())); done <- struct{}{} }()
	<-done
}

// pumpBufSize 返回数据泵缓冲字节数，默认 512KB，可用 TUNNEL_PUMP_BUF 覆盖（压测用）。
func pumpBufSize() int {
	if v := os.Getenv("TUNNEL_PUMP_BUF"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 4096 {
			return n
		}
	}
	return 512 * 1024
}

// loadKey loads a private key from a file path or hex string. Empty path
// means generate a fresh identity (NodeID changes each run).
func loadKey(path string) (*ecdh.PrivateKey, error) {
	if path == "" {
		return nil, nil
	}
	if _, err := os.Stat(path); err == nil {
		return natnode.LoadPrivateKeyFromFile(path)
	}
	return natnode.LoadPrivateKeyFromHex(path)
}
