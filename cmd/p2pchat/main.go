// P2P 聊天控制台程序。
//
// 启动后选择模式:
//
//	index <listen> [public]            启动 index 节点(中继中心)
//	relay <listen> 启动中转服务器;
//	node  <addr> [keyFile]        启动 NAT 节点; addr 为 index 时 bootstrap 就近选 relay；
//	                              keyFile 可选，指向之前 /save 导出的私钥文件，
//	                              用于以同一身份再次上线。
//	quit                          退出程序
//
// 进入 NAT 节点模式后:
//
//	-c <NodeId>     连接到目标节点
//	-q              断开当前活动连接
//	/list           列出已知邻居
//	/key            打印本节点私钥 hex（妥善保管）
//	/save <path>    把本节点私钥保存到文件
//	/exit           关闭当前节点，返回模式选择
//	其他输入         发送消息到当前活动连接
package main

import (
	"bufio"
	"context"
	"crypto/ecdh"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"bnfs_p2p/logx"
	"bnfs_p2p/p2pnode"
	"bnfs_p2p/p2pnode/impl/natnode"
	"bnfs_p2p/p2pnode/impl/relaynode"
)

// defaultIndexAddr 是默认的 index 节点地址(中继中心)。
// p2p.stationchange.cn 当前解析到作为 index server 的那台机器。
//   - relay 启动后默认向它注册自己为 relay 邻居(可由 relay 命令第 4 个参数覆盖);
//   - node 启动后默认经它 bootstrap 就近选 relay(可由 node 命令第 1 个参数覆盖);
//   - index 自身不向任何节点注册。
const defaultIndexAddr = "p2p.stationchange.cn:9000"

// stdinScanner 是全进程共享的标准输入扫描器。
// 必须全局唯一: bufio.Scanner 会按块缓冲读取, 若 main 与各子控制台(relay/node)各建一个,
// 先读的那个可能把后续行也缓冲进去, 导致另一个 Scanner 丢失输入(管道输入下尤其明显)。
var stdinScanner = bufio.NewScanner(os.Stdin)

func main() {
	fmt.Println("=== P2P 聊天 ===")
	scanner := stdinScanner

	for {
		fmt.Println()
		fmt.Println("可用模式:")
		fmt.Println("  relay <listen> [public] [indexAddr] 启动中转服务器; 默认自动注册到 " + defaultIndexAddr + "; 启动后 /list 查看状态")
		fmt.Println("  node  <addr> [keyFile]             启动 NAT 节点; 默认经 " + defaultIndexAddr + " bootstrap 就近选 relay")
		fmt.Println("                                     addr 不可达/非地址或填 \"-\" 时, 自动回退到默认 index")
		fmt.Println("  quit                               退出程序")
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		switch fields[0] {
		case "quit":
			fmt.Println("再见!")
			return
		case "index":
			listen := ":9000"
			if len(fields) > 1 {
				listen = fields[1]
			}
			public := ""
			if len(fields) > 2 {
				public = fields[2]
			}
			// index server: 静音注册/登记/转发等监控信息, 只保留报错+堆栈。
			logx.SetLevel(logx.LevelError)
			startRelay(listen, public, "")
		case "relay":
			listen := ":9000"
			if len(fields) > 1 {
				listen = fields[1]
			}
			// public 留空: 由框架按监听地址/对端观察到的 IP 推断, 不再误用 index 的地址。
			public := ""
			if len(fields) > 2 {
				public = fields[2]
			}
			// relay 默认自动注册到 index(defaultIndexAddr); 传第 4 个参数可覆盖目标 index。
			indexAddr := defaultIndexAddr
			if len(fields) > 3 {
				indexAddr = fields[3]
			}
			// 普通中转 / 节点模式保留常规监控信息(若上一条 index 命令调过 Error 级, 这里复位)。
			logx.SetLevel(logx.LevelInfo)
			startRelay(listen, public, indexAddr)
		case "node":
			// addr 默认走 defaultIndexAddr bootstrap。允许用户只关注 keyFile:
			//   - 填特殊指令 "-"(或 "_"/"default"): 显式跳过该字段, 直接用默认 index;
			//   - 填了地址但网络不可达 / 压根不是个有效 host:port: 自动回退默认 index。
			addr := defaultIndexAddr
			if len(fields) > 1 {
				addr = resolveNodeAddr(fields[1])
			}
			keyFile := ""
			if len(fields) > 2 {
				keyFile = fields[2]
			}
			logx.SetLevel(logx.LevelInfo)
			runNode(addr, keyFile)
		default:
			fmt.Printf("未知模式: %s\n", fields[0])
		}
	}
}

// -- NAT 节点聊天会话 --

type chatSession struct {
	node p2pnode.Node

	activeConn p2pnode.Connection
	activePeer p2pnode.NodeID

	receiveStarted map[p2pnode.NodeID]bool

	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
}

func runNode(relayAddr string, keyFile string) {
	// 若指定 keyFile, 从文件加载私钥以恢复同一身份；否则 NewNATNode(nil,...) 自动生成。
	privKey, err := loadKeyIfRequested(keyFile)
	if err != nil {
		fmt.Printf("加载私钥失败: %v\n", err)
		return
	}
	if privKey != nil {
		fmt.Printf("已从 %q 加载私钥, 将恢复原节点身份\n", keyFile)
	}

	node, err := natnode.NewNATNode(privKey, relayAddr)
	if err != nil {
		fmt.Printf("创建节点失败: %v\n", err)
		return
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &chatSession{
		node:           node,
		receiveStarted: make(map[p2pnode.NodeID]bool),
		ctx:            ctx,
		cancel:         cancel,
	}

	// 入站连接回调：显示连接信息，自动设为活动并启动接收协程。
	node.OnConnection(func(conn p2pnode.Connection) {
		peer := conn.Peer()
		s.mu.Lock()
		s.activeConn = conn
		s.activePeer = peer.ID
		s.receiveStarted[peer.ID] = true
		s.mu.Unlock()
		fmt.Printf("\n[入站连接] 节点 %s 已连接\n> ", peer.ID)
		go s.receiveLoop(conn)
	})

	fmt.Printf("本节点 ID: %s\n", node.ID())

	// 经 relayAddr bootstrap: 若它是 index 会返回就近可达的入口 relay(不可达回退次近/index);
	// 若它本就是普通 relay, bootstrap 查询失败会原样回退到该地址。对两种情况都正确。
	entryRelay, _ := node.Bootstrap(ctx, relayAddr)
	fmt.Printf("注册到 relay: %s\n", entryRelay)

	// 启动 Listen。
	go func() {
		if err := node.Listen(ctx, entryRelay); err != nil {
			fmt.Printf("\nListen 退出: %v\n", err)
		}
	}()

	time.Sleep(500 * time.Millisecond)

	fmt.Println("\n可用命令:")
	fmt.Println("  -c <NodeId>     连接到目标节点")
	fmt.Println("  -q              断开当前活动连接")
	fmt.Println("  /list           列出已知邻居")
	fmt.Println("  /key            打印本节点私钥 hex (妥善保管)")
	fmt.Println("  /save <path>    把本节点私钥保存到文件")
	fmt.Println("  /exit           关闭当前节点，返回模式选择")
	fmt.Println("  其他输入         发送消息到当前活动连接")
	fmt.Println()

	scanner := stdinScanner

	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		switch {
		case line == "/exit":
			cancel()
			node.Close()
			fmt.Printf("节点 %s 已关闭，返回模式选择\n", node.ID())
			return

		case line == "/key":
			fmt.Printf("私钥(hex): %s\n", node.ExportPrivateKeyHex())
			fmt.Println("提示: 持有该字符串等同于持有节点身份, 请妥善保管")

		case strings.HasPrefix(line, "/save"):
			parts := strings.Fields(line)
			if len(parts) < 2 {
				fmt.Println("用法: /save <path>")
				continue
			}
			path := parts[1]
			if err := node.SavePrivateKey(path); err != nil {
				fmt.Printf("保存失败: %v\n", err)
				continue
			}
			fmt.Printf("私钥已保存到 %q (权限 0600)\n", path)

		case line == "-q":
			s.mu.Lock()
			peer := s.activePeer
			conn := s.activeConn
			if peer == "" {
				s.mu.Unlock()
				fmt.Println("当前无活动连接")
				continue
			}
			s.activeConn = nil
			s.activePeer = ""
			delete(s.receiveStarted, peer)
			s.mu.Unlock()
			if conn != nil {
				conn.Close()
			}
			fmt.Printf("断开与 %s 的连接\n", peer)

		case line == "/list":
			neighbors := node.Neighbors()
			if len(neighbors) == 0 {
				fmt.Println("暂无已知邻居")
				continue
			}
			s.mu.Lock()
			active := s.activePeer
			s.mu.Unlock()
			fmt.Printf("已知邻居 (%d 个):\n", len(neighbors))
			for _, p := range neighbors {
				m := " "
				if p.ID == active {
					m = "*"
				}
				fmt.Printf(" %s %s  (%s)\n", m, p.ID, p.LastSeen.Format("15:04:05"))
			}

		case strings.HasPrefix(line, "-c "):
			targetID := p2pnode.NodeID(strings.TrimSpace(line[3:]))
			if len(targetID) != 64 {
				fmt.Printf("无效的 NodeID 长度: %d (应为64位hex)\n", len(targetID))
				continue
			}
			if targetID == node.ID() {
				fmt.Println("不能连接自身")
				continue
			}
			fmt.Printf("正在连接到 %s ...\n", targetID)
			conn, err := node.Connect(s.ctx, targetID)
			if err != nil {
				fmt.Printf("连接失败: %v\n", err)
				continue
			}
			s.mu.Lock()
			s.activeConn = conn
			s.activePeer = targetID
			isNew := !s.receiveStarted[targetID]
			if isNew {
				s.receiveStarted[targetID] = true
			}
			s.mu.Unlock()
			if isNew {
				fmt.Printf("已连接到 %s\n", targetID)
				go s.receiveLoop(conn)
			} else {
				fmt.Printf("已切换到与 %s 的会话\n", targetID)
			}

		default:
			s.mu.Lock()
			conn := s.activeConn
			s.mu.Unlock()
			if conn == nil {
				fmt.Println("无活动连接，请先使用 -c <NodeId> 连接目标节点")
				continue
			}
			msg := &p2pnode.Message{
				Type:    p2pnode.MsgAppData,
				Payload: []byte(line),
			}
			if err := conn.Send(s.ctx, msg); err != nil {
				fmt.Printf("发送失败: %v\n", err)
			}
		}
	}
}

// resolveNodeAddr 规整 node 模式的 addr 参数, 让用户可以只关注 keyFile:
//   - 特殊指令 "-" / "_" / "default"(大小写不敏感): 显式跳过该字段, 用 defaultIndexAddr;
//   - 不含端口 / 不是合法 host:port: 视为误填, 回退 defaultIndexAddr;
//   - 是合法 host:port 但短超时 TCP 探测不可达: 回退 defaultIndexAddr;
//   - 其余(可达)原样返回。
// 注意: 即便返回 defaultIndexAddr, 后续 Bootstrap 仍会做一次完整查询/可达性回退,
// 这里只是把"明显无效/不可达"的输入提前挡掉, 避免卡在一个连不上的自定义地址上。
func resolveNodeAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	switch strings.ToLower(addr) {
	case "", "-", "_", "default":
		fmt.Printf("跳过 addr 解析, 使用默认 index: %s\n", defaultIndexAddr)
		return defaultIndexAddr
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		fmt.Printf("addr %q 不是合法的 host:port, 回退默认 index: %s\n", addr, defaultIndexAddr)
		return defaultIndexAddr
	}
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		fmt.Printf("addr %q 不可达(%v), 回退默认 index: %s\n", addr, err, defaultIndexAddr)
		return defaultIndexAddr
	}
	_ = conn.Close()
	return addr
}

// loadKeyIfRequested 当 path 非空时, 优先按文件路径加载, 路径不存在则当作 hex 字符串解析,
// 这样用户既能 `node <relay> ./mykey.hex`, 也能 `node <relay> <粘贴的64位hex>`.
// 返回 nil 私钥表示用户未指定 keyFile, 由 NewNATNode 自动生成新身份。
func loadKeyIfRequested(path string) (*ecdh.PrivateKey, error) {
	if path == "" {
		return nil, nil
	}
	if _, statErr := os.Stat(path); statErr == nil {
		return natnode.LoadPrivateKeyFromFile(path)
	}
	return natnode.LoadPrivateKeyFromHex(path)
}

func (s *chatSession) receiveLoop(conn p2pnode.Connection) {
	peerID := conn.Peer().ID
	for {
		msg, err := conn.Receive(s.ctx)
		if err != nil {
			fmt.Printf("\n[断开] %s\n> ", peerID)
			s.mu.Lock()
			delete(s.receiveStarted, peerID)
			if s.activePeer == peerID {
				s.activeConn = nil
				s.activePeer = ""
			}
			s.mu.Unlock()
			return
		}
		fmt.Printf("\n[%s] %s\n> ", peerID, string(msg.Payload))
	}
}

// -- 中转服务器 / index --

// startRelay 启动一个 RelayNode。index 本质是无上级的 RelayNode。
// indexAddr 非空时, 启动后向 index 注册成为其邻居。
// 启动后进入一个简单控制台: /list 查看本 relay 邻居与已注册 NAT 节点, /exit 关闭并返回模式选择。
func startRelay(listen, public, indexAddr string) {
	rn, err := relaynode.NewRelayNode(nil, listen, public)
	if err != nil {
		fmt.Printf("创建 relay 节点失败: %v\n", err)
		return
	}
	fmt.Printf("RelayNode ID: %s\n", rn.ID())
	fmt.Printf("监听: %s  对外地址: %s\n", listen, rn.Addr())
	if indexAddr != "" {
		fmt.Printf("正在向 index 注册(只需地址, 其 ID 将自动获知): %s\n", indexAddr)
		rn.RegisterToIndex(indexAddr, func(indexID, addr string) {
			fmt.Printf("已注册到 index: id=%s addr=%s\n", indexID, addr)
		})
	}

	// Start 阻塞, 放后台跑; 主线程进入控制台读命令。
	go rn.Start()

	fmt.Println("控制台命令: /list 查看 relay 邻居与已注册 NAT 节点 | /exit 关闭并返回")
	scanner := stdinScanner
	for {
		fmt.Print("(relay)> ")
		if !scanner.Scan() {
			break
		}
		switch strings.TrimSpace(scanner.Text()) {
		case "":
			continue
		case "/list":
			printRelayStatus(rn)
		case "/exit":
			_ = rn.Close()
			fmt.Println("已关闭 relay, 返回模式选择。")
			return
		default:
			fmt.Println("未知命令; 可用: /list, /exit")
		}
	}
}

// printRelayStatus 打印本 relay 的当前状态: relay 邻居(对端中转节点) + 已注册的 NAT 节点。
func printRelayStatus(rn *relaynode.RelayNode) {
	neighbors := rn.RelayNeighbors()
	hosted := rn.HostedNatNodesDetailed()
	fmt.Printf("本节点 ID: %s\n", rn.ID())
	fmt.Printf("relay 邻居=%d  已注册 NAT 节点=%d\n", len(neighbors), len(hosted))
	for _, p := range neighbors {
		addr := ""
		if len(p.Addresses) > 0 {
			addr = p.Addresses[0].Relay
		}
		fmt.Printf("    [relay邻居] id=%s addr=%s\n", p.ID, addr)
	}
	for _, h := range hosted {
		src := h.RemoteAddr
		if src == "" {
			src = "(未知)"
		}
		fmt.Printf("    [NAT节点] id=%s 来源=%s\n", h.NodeID, src)
	}
}
