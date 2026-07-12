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
	"strconv"
	"strings"
	"time"

	"bnfs_p2p/admissioncli"
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
	caURL := flag.String("ca", "", "CA/indexServer web 地址; 给了即带 client 角色 indexSign 注册")
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

	// tunnel client = client 角色：申请 client 证书并注入。-ca 为空则不启用。
	if err := admissioncli.SetupNat(node, *caURL, admissioncli.RoleClient()); err != nil {
		log.Fatalf("申请 indexSign 失败: %v", err)
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

// pipe copies bytes in both directions. 朝 mux 写的方向(dst=a=stream)用 accumCopy 聚合:
// 单次阻塞读后在短窗内贪婪 drain 源上已就绪的字节、填满 pumpBuf 再一次 Write，让每条 mux
// 消息携带 W×chunk 字节、激活 W 个并发 sendData(在途深度→W 而非 1)，跨区高 RTT 大幅提速。
// 反方向(源为 mux stream，发端已聚合)用普通 CopyBuffer。
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
// 小请求(如 HTTP GET)干等——首段一到、短窗内无更多数据就立即 flush。
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
		// 首段:阻塞读(清除任何遗留 deadline)
		_ = dr.SetReadDeadline(time.Time{})
		n, rerr := src.Read(buf)
		if n > 0 {
			// 短窗内贪婪 drain:把源上"此刻已就绪"的字节尽量填满 buf
			if n < len(buf) && rerr == nil {
				_ = dr.SetReadDeadline(time.Now().Add(window))
				for n < len(buf) {
					m, derr := src.Read(buf[n:])
					n += m
					if derr != nil {
						// 超时(drain 结束)或真错误:都停止 drain，下面统一处理
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
// 窗口越大聚合越充分(吞吐↑)但小请求延迟越高;2ms 在 31ms RTT 下几乎无感。
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

func loadKey(path string) (*ecdh.PrivateKey, error) {
	if path == "" {
		return nil, nil
	}
	if _, err := os.Stat(path); err == nil {
		return natnode.LoadPrivateKeyFromFile(path)
	}
	return natnode.LoadPrivateKeyFromHex(path)
}
