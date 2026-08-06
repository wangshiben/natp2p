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
	relayAddrs := flag.String("relays", "", "comma-separated service Relay addresses (maximum 3)")
	relayCount := flag.Int("relay-count", 1, "number of quality-ranked service Relays to register (1-3)")
	target := flag.String("target", "127.0.0.1:5173", "local TCP address to forward traffic to")
	keyFile := flag.String("key", "", "optional private key file to keep a stable NodeID")
	caURL := flag.String("ca", "", "CA/indexServer web 地址; 给了即带 server 角色 indexSign 注册(计费对象)")
	billingPrivateSnapshot := flag.String("billing-private-snapshot", "", "私有计费快照 JSON 路径（父目录 0700、文件 0600）")
	maxSessions := flag.Int("max-sessions", 8, "maximum independent NatClient service sessions")
	acceptQueue := flag.Int("accept-queue", 8, "pending authenticated service sessions")
	statusFile := flag.String("status-file", "", "optional service listener status JSON path")
	serviceName := flag.String("service-name", "", "service name included in listener status")
	flag.Parse()
	if *relayCount < 1 || *relayCount > 3 {
		logx.Errorf("relay-count 必须在 1..3 之间")
		os.Exit(1)
	}
	if *relayAddr != "" && *relayAddrs != "" {
		logx.Errorf("-relay 与 -relays 不能同时使用")
		os.Exit(1)
	}

	privKey, err := loadKey(*keyFile)
	if err != nil {
		logx.Errorf("加载私钥失败: %v", err)
		os.Exit(1)
	}

	// If a relay is pinned, use it as the bootstrap relay so it becomes this
	// node's sole entry relay (NewNATNode registers bootstrapRelay in
	// entryRelays, and NAT nodes only dial via their own entry relay).
	bootstrapAddr := *indexAddr
	configuredRelays := splitRelayAddresses(*relayAddrs)
	if len(configuredRelays) > 0 {
		bootstrapAddr = configuredRelays[0]
	} else if *relayAddr != "" {
		bootstrapAddr = *relayAddr
	}
	node, err := natnode.NewNATNode(privKey, bootstrapAddr)
	if err != nil {
		logx.Errorf("创建节点失败: %v", err)
		os.Exit(1)
	}
	if err := node.SetBillingPrivateSnapshotPath(*billingPrivateSnapshot); err != nil {
		_ = node.Close()
		logx.Errorf("初始化私有计费快照失败: %v", err)
		os.Exit(1)
	}

	// tunnel server = server 角色（计费对象）：申请 server 证书并注入。-ca 为空则不启用。
	if err := admissioncli.SetupNat(node, *caURL, admissioncli.RoleServer()); err != nil {
		logx.Errorf("申请 indexSign 失败: %v", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Printf("=== Tunnel Server ===\n")
	fmt.Printf("本节点 ID: %s\n", node.ID())
	fmt.Printf("转发目标: %s\n", *target)

	// Entry relay selection. By default Bootstrap auto-picks a relay by XOR
	// distance from this node's ID, which means server and client can land on
	// different relays. If cross-relay bridging is unreliable, pin both ends to
	// the same relay with -relay.
	var serviceRelays []string
	if len(configuredRelays) > 0 {
		serviceRelays = configuredRelays
		fmt.Printf("使用指定 Relays: %s\n", strings.Join(serviceRelays, ","))
	} else if *relayAddr != "" {
		serviceRelays = []string{*relayAddr}
		fmt.Printf("使用指定 relay: %s\n", serviceRelays[0])
	} else {
		entryRelay, _ := node.Bootstrap(ctx, *indexAddr)
		serviceRelays = node.RelayCandidates(*relayCount)
		if len(serviceRelays) == 0 {
			serviceRelays = []string{entryRelay}
		}
		fmt.Printf("注册到 relay: %s\n", entryRelay)
		if len(serviceRelays) > 1 {
			fmt.Printf("服务多 Relay: %s\n", strings.Join(serviceRelays, ","))
		}
	}

	serviceOptions := natnode.ServiceOptions{
		MaxSessions: *maxSessions,
		AcceptQueue: *acceptQueue,
	}
	var listener *natnode.ServiceListener
	if len(serviceRelays) == 1 {
		listener, err = node.ListenService(ctx, serviceRelays[0], serviceOptions)
	} else {
		listener, err = node.ListenServiceRelays(ctx, serviceRelays, serviceOptions)
	}
	if err != nil {
		logx.Errorf("启动持久服务注册失败: %v", err)
		os.Exit(1)
	}
	defer listener.Close()
	if err := startServiceStatusReporter(ctx, *statusFile, *serviceName, string(node.ID()), listener); err != nil {
		logx.Errorf("启动服务会话状态上报失败: %v", err)
		os.Exit(1)
	}
	go serveServiceSessions(ctx, listener, *target)

	fmt.Printf("\n服务端已就绪，等待客户端连接（最多 %d 条独立会话）。客户端使用上面的 NodeID 连接。\n", *maxSessions)
	fmt.Println("按 Ctrl+C 退出。")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	fmt.Println("\n正在关闭...")
	cancel()
	node.Close()
}

func splitRelayAddresses(value string) []string {
	unique := make([]string, 0, 3)
	seen := make(map[string]struct{})
	for _, relay := range strings.Split(value, ",") {
		relay = strings.TrimSpace(relay)
		if relay == "" {
			continue
		}
		if _, exists := seen[relay]; exists {
			continue
		}
		seen[relay] = struct{}{}
		unique = append(unique, relay)
	}
	return unique
}

func serveServiceSessions(ctx context.Context, listener *natnode.ServiceListener, target string) {
	for {
		connection, err := listener.Accept(ctx)
		if err != nil {
			if ctx.Err() == nil {
				logx.Errorf("服务接入循环退出: %v", err)
			}
			return
		}
		peer := connection.Peer()
		fmt.Printf("[隧道] 客户端 %s 已连接\n", peer.ID)
		go handleTunnel(ctx, connection, target)
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
		logx.Warnf("拨号本地 %s 失败: %v", target, err)
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
