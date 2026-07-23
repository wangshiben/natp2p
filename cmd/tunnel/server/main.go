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
	"strings"
	"syscall"
	"time"

	"bnfs_p2p/admissioncli"
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
	caURL := flag.String("ca", "", "CA/indexServer web 地址; 给了即带 server 角色 indexSign 注册(计费对象)")
	billingPrivateSnapshot := flag.String("billing-private-snapshot", "", "私有计费快照 JSON 路径（父目录 0700、文件 0600）")
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
	if err := node.SetBillingPrivateSnapshotPath(*billingPrivateSnapshot); err != nil {
		_ = node.Close()
		log.Fatalf("初始化私有计费快照失败: %v", err)
	}

	// tunnel server = server 角色（计费对象）：申请 server 证书并注入。-ca 为空则不启用。
	if err := admissioncli.SetupNat(node, *caURL, admissioncli.RoleServer()); err != nil {
		log.Fatalf("申请 indexSign 失败: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Each inbound P2P connection becomes a tunnel session.
	node.OnConnection(func(conn p2pnode.Connection) {
		peer := conn.Peer()
		fmt.Printf("[隧道] 客户端 %s 已连接\n", peer.ID)
		handleTunnel(ctx, conn, *target)
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

	// Listen consumes one registration stream per inbound connection. The
	// callback above runs synchronously until that mux session has closed, so
	// each new registration starts only after the previous tunnel is gone.
	go serveTunnelSessions(ctx, node, entryRelay)

	fmt.Println("\n服务端已就绪，等待客户端连接。客户端使用上面的 NodeID 连接。")
	fmt.Println("按 Ctrl+C 退出。")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("\n正在关闭...")
	cancel()
	node.Close()
}

type tunnelListener interface {
	Listen(context.Context, string) error
}

func serveTunnelSessions(ctx context.Context, listener tunnelListener, entryRelay string) {
	retryDelay := 250 * time.Millisecond
	const maximumRetryDelay = 5 * time.Second
	for ctx.Err() == nil {
		if err := listener.Listen(ctx, entryRelay); err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("Listen 退出，将重试: %v", err)
			timer := time.NewTimer(retryDelay)
			select {
			case <-ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return
			case <-timer.C:
			}
			if retryDelay < maximumRetryDelay {
				retryDelay *= 2
				if retryDelay > maximumRetryDelay {
					retryDelay = maximumRetryDelay
				}
			}
			continue
		}
		retryDelay = 250 * time.Millisecond
	}
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
// 朝 mux 写的方向(dst=a=stream)用 accumCopy 聚合:单次阻塞读后在短窗内贪婪 drain 源上
// 已就绪字节、填满 pumpBuf 再一次 Write，让每条 mux 消息携带 W×chunk 字节、激活 W 个并发
// sendData(在途深度→W 而非 1)。这是下载大流(httpfile→mux)的关键路径。反方向(源为 mux
// stream,发端已聚合)用普通 CopyBuffer。
func pipe(a io.ReadWriteCloser, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() { accumCopy(a, b, pumpBufSize()); done <- struct{}{} }()
	go func() { io.CopyBuffer(b, a, make([]byte, pumpBufSize())); done <- struct{}{} }()
	<-done
}

// deadlineReader 是支持读超时的源(如 *net.TCPConn)，用于 accumCopy 的贪婪 drain。
type deadlineReader interface {
	SetReadDeadline(t time.Time) error
}

// accumCopy 从 src 拷到 dst，聚合小段:每轮先做一次阻塞读拿到首段数据，再在
// coalesceWindow 短窗内非阻塞地把源上已就绪的字节继续读进同一 buf(填满即止)，
// 然后一次性 Write。既能把连续大流(下载)合成满 buf 写(depth→W)，又不会让
// 小响应干等——首段一到、短窗内无更多数据就立即 flush。
// src 若不支持 SetReadDeadline 则回退普通 CopyBuffer。
func accumCopy(dst io.Writer, src io.Reader, bufSize int) (int64, error) {
	dr, ok := src.(deadlineReader)
	if !ok {
		return io.CopyBuffer(dst, src, make([]byte, bufSize))
	}
	buf := make([]byte, bufSize)
	window := coalesceWindow()
	var total int64
	for {
		_ = dr.SetReadDeadline(time.Time{})
		n, rerr := src.Read(buf)
		if n > 0 {
			if n < len(buf) && rerr == nil {
				_ = dr.SetReadDeadline(time.Now().Add(window))
				for n < len(buf) {
					m, derr := src.Read(buf[n:])
					n += m
					if derr != nil {
						if ne, isNet := derr.(net.Error); isNet && ne.Timeout() {
							rerr = nil
						} else {
							rerr = derr
						}
						break
					}
				}
				_ = dr.SetReadDeadline(time.Time{})
			}
			wn, werr := dst.Write(buf[:n])
			total += int64(wn)
			if werr != nil {
				return total, werr
			}
			if wn < n {
				return total, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return total, nil
			}
			return total, rerr
		}
	}
}

// coalesceWindow 返回贪婪 drain 的短窗时长，默认 2ms，可用 TUNNEL_COALESCE_MS 覆盖。
func coalesceWindow() time.Duration {
	if v := os.Getenv("TUNNEL_COALESCE_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return time.Duration(n) * time.Millisecond
		}
	}
	return 2 * time.Millisecond
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
	if strings.ContainsRune(path, os.PathSeparator) {
		return natnode.LoadOrCreatePrivateKeyFile(path)
	}
	return natnode.LoadPrivateKeyFromHex(path)
}
