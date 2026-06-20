// relaychat 是 relayNode 跨中继能力的验证程序（参考 cmd/p2pchat/main.go）。
//
// 四种运行模式（flag 驱动, 便于脚本化双服务器部署）：
//
//	-mode relay   -listen :9000 [-public IP:9000] [-peer IP2:9000[,IP3:9000]] [-key file]
//	    启动一个公网中继节点（RelayNode）。
//	    -listen  本地监听地址（如 0.0.0.0:9000）。
//	    -public  对外可达地址（如 1.2.3.4:9000）；为空时回退用 -listen, 仅适合本机测试。
//	    -peer    要主动建立控制链路的对端 relay 地址, 逗号分隔可填多个;
//	             控制链路用于跨中继 FIND, 任一端发起即可（双向对称）。
//	    每 5 秒打印一次状态: relay 邻居数 / 本地托管的 NAT 节点数。
//
//	-mode listen  -relay IP:9000 [-key file]
//	    启动一个 NAT 节点, 注册到 -relay 指定的中继, 对收到的每条消息回显 "echo:<原文>"。
//	    启动后打印自身 NodeID（供 connect 方作为 -target 使用）。进程阻塞直到 Ctrl+C / SIGTERM。
//
//	-mode connect -relay IP:9000 -target <NodeID> [-rounds 3] [-msg hello] [-key file]
//	    启动一个 NAT 节点, 注册到 -relay, 连接 -target 节点并发起 -rounds 轮请求/响应通信:
//	    每轮发送 "<msg>-<i>" 并等待对端回包。target 与本节点可注册在不同的 relay 上,
//	    入口 relay 会经控制链路 FIND 到托管 target 的 relay 并跨中继桥接。
//	    全部轮次成功退出码 0, 否则非 0。
//
//	-mode interactive   进入交互式控制台（默认模式, 行为接近 p2pchat）。
//	    在控制台中:
//	      relay <listen> [peer]    启动中继节点(阻塞)
//	      node  <relayAddr> [key]  启动 NAT 节点并进入聊天会话
//	    进入 node 聊天会话后支持: -c <NodeId> 连接、直接输入文本发消息、自动显示
//	    收到的消息、/list 列邻居、/who 看身份、/key /save 管理私钥、/exit 退出。
//
// 通用 flag:
//
//	-key <file|hex>   可选。以指定私钥恢复同一节点身份再次上线（文件路径或直接粘贴 hex）。
//
// ── 端到端示例（双公网服务器跨中继, 与 pacakgeTest 验证一致）──
//
// 服务器1 (relay1, 公网 IP 203.0.113.1) 上启动中继:
//
//	relaychat -mode relay -listen 0.0.0.0:9000 -public 203.0.113.1:9000
//
// 服务器2 (relay2, 公网 IP 198.51.100.1) 上启动中继, 并与 relay1 建控制链路:
//
//	relaychat -mode relay -listen 0.0.0.0:9000 -public 198.51.100.1:9000 -peer 203.0.113.1:9000
//
// 本地节点2 注册到 relay2, 进入回显模式, 记下打印出的 NodeID（记为 NODE2）:
//
//	relaychat -mode listen -relay 198.51.100.1:9000
//
// 本地节点1 经 relay1 跨中继连接 NODE2, 做 3 轮通信:
//
//	relaychat -mode connect -relay 203.0.113.1:9000 -target <NODE2> -rounds 3 -msg hello
//
// 预期: 节点1 打印 "成功 3/3 轮", 节点2 打印 3 行 "[收到] ... hello-0/1/2"。
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
	"sync"
	"syscall"
	"time"

	"bnfs_p2p/p2pnode"
	"bnfs_p2p/p2pnode/impl/natnode"
	"bnfs_p2p/p2pnode/impl/relaynode"
)

func main() {
	mode := flag.String("mode", "interactive", "运行模式: index | relay | listen | connect | interactive")
	listen := flag.String("listen", ":9000", "relay 监听地址 (index/relay 模式)")
	public := flag.String("public", "", "relay 对外可达地址 (index/relay 模式, 默认同 listen)")
	peer := flag.String("peer", "", "要建立控制链路的对端 relay 地址, 逗号分隔 (relay 模式)")
	index := flag.String("index", "", "index 节点地址: relay 模式下启动后向其注册; listen/connect 模式下经它 bootstrap 就近选 relay")
	relayAddr := flag.String("relay", "127.0.0.1:9000", "直连的 relay 地址 (listen/connect 模式, 与 -index 二选一)")
	target := flag.String("target", "", "目标 NodeID (connect 模式)")
	rounds := flag.Int("rounds", 3, "通信轮数 (connect 模式)")
	msg := flag.String("msg", "hello", "每轮消息前缀 (connect 模式)")
	connTimeout := flag.Int("connTimeout", 15, "连接/每轮接收的超时秒数 (connect 模式; 跨境多跳链路可调大)")
	keyFile := flag.String("key", "", "私钥文件, 用同一身份再次上线")
	flag.Usage = printUsage
	flag.Parse()

	switch *mode {
	case "index":
		// index 本质 = 无上级(无 -peer)的 RelayNode。
		runRelay(*listen, *public, "", "", *keyFile)
	case "relay":
		runRelay(*listen, *public, *peer, *index, *keyFile)
	case "listen":
		runListen(*relayAddr, *index, *keyFile)
	case "connect":
		runConnect(*relayAddr, *index, *target, *rounds, *msg, *keyFile, *connTimeout)
	case "interactive":
		runInteractive()
	default:
		fmt.Printf("未知模式: %s\n\n", *mode)
		printUsage()
		os.Exit(1)
	}
}

// printUsage 打印各模式用法与一个跨中继端到端示例。
func printUsage() {
	fmt.Fprint(os.Stderr, `relaychat — relayNode 跨中继验证程序

用法:
  relaychat -mode index   -listen :9000 [-public IP:9000] [-key file]
  relaychat -mode relay   -listen :9000 [-public IP:9000] [-index IDX:9000] [-peer IP2:9000[,IP3:9000]] [-key file]
  relaychat -mode listen  (-index IDX:9000 | -relay IP:9000) [-key file]
  relaychat -mode connect (-index IDX:9000 | -relay IP:9000) -target <NodeID> [-rounds 3] [-msg hello] [-key file]
  relaychat -mode interactive

模式:
  index        启动 index 节点(无上级的中继中心), 接受 relay/NAT 节点注册
  relay        启动公网中继节点; -index 指定启动后注册到的 index; -peer 指定要建链的对端 relay
  listen       注册到 relay 并回显收到的每条消息; 打印自身 NodeID; 阻塞至 Ctrl+C
               给 -index 则先 bootstrap 就近选 relay(不可达回退次近/index), 否则直连 -relay
  connect      经 relay 跨中继连接 -target 并做 -rounds 轮请求/响应(同样支持 -index bootstrap)
  interactive  交互式控制台(默认)

三机端到端示例(server1=index, server2=relay, server3=server/callee, 本机=client):
  # server1 (38.0.0.1) 起 index
  relaychat -mode index -listen 0.0.0.0:9000 -public 38.0.0.1:9000
  # server2 (104.0.0.1) 起 relay 并注册到 index
  relaychat -mode relay -listen 0.0.0.0:9000 -public 104.0.0.1:9000 -index 38.0.0.1:9000
  # server3 (129.0.0.1) 起 callee, 经 index bootstrap(试 server2 不可达→回退 index), 记下 NodeID
  relaychat -mode listen -index 38.0.0.1:9000
  # 本机 client 经 index bootstrap(命中 server2), 跨中继连接 callee, 3 轮通信
  relaychat -mode connect -index 38.0.0.1:9000 -target <NodeID> -rounds 3 -msg hello

flags:
`)
	flag.PrintDefaults()
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
// index 非空时, 启动后向 index 注册成为其邻居（建可重试控制链路）。
func runRelay(listen, public, peer, index, keyFile string) {
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

	if index != "" {
		fmt.Printf("正在向 index 注册(只需地址, 其 ID 将自动获知): %s\n", index)
		rn.RegisterToIndex(index, func(indexID, addr string) {
			fmt.Printf("已注册到 index: id=%s addr=%s\n", indexID, addr)
		})
	}

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
			neighbors := rn.RelayNeighbors()
			hosted := rn.HostedNatNodesDetailed()
			fmt.Printf("[状态] relay邻居=%d 托管NAT节点=%d\n", len(neighbors), len(hosted))
			// 打印每个对端 relay 邻居及其地址。
			for _, p := range neighbors {
				addr := ""
				if len(p.Addresses) > 0 {
					addr = p.Addresses[0].Relay
				}
				fmt.Printf("    [relay邻居] id=%.16s addr=%s\n", p.ID, addr)
			}
			// 打印每个托管的 NAT 节点及其托管来源地址（底层连接远端 IP:port）。
			for _, h := range hosted {
				src := h.RemoteAddr
				if src == "" {
					src = "(未知)"
				}
				fmt.Printf("    [托管NAT] id=%.16s 来源=%s\n", h.NodeID, src)
			}
		}
	}()

	rn.Start() // 阻塞
}

// runListen 启动一个 NAT 节点, 注册到 relay, 对每条消息回显。
// index 非空时先经 index bootstrap 就近选定入口 relay（不可达回退次近/index）; 否则直连 relayAddr。
func runListen(relayAddr, index, keyFile string) {
	privKey, err := loadKey(keyFile)
	if err != nil {
		fmt.Printf("加载私钥失败: %v\n", err)
		os.Exit(1)
	}
	bootstrapAddr := relayAddr
	if index != "" {
		bootstrapAddr = index
	}
	node, err := natnode.NewNATNode(privKey, bootstrapAddr)
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

	// 若给了 index, 先 bootstrap 选定入口 relay。
	entryRelay := relayAddr
	if index != "" {
		entry, err := node.Bootstrap(ctx, index)
		if err != nil {
			fmt.Printf("bootstrap 失败: %v\n", err)
			os.Exit(1)
		}
		entryRelay = entry
	}
	fmt.Printf("注册到 relay: %s\n", entryRelay)
	fmt.Println("等待入站连接, 将对每条消息回显 echo:<原文> ...")

	// 注意：natnode.Listen 在首个入站连接被消费后即返回（注册流被复用为该连接）,
	// 但我们要持续为已建立的连接服务（echoLoop 在 OnConnection 回调里运行）, 因此 Listen 返回后
	// 不能退出 runListen（否则 defer node.Close()/cancel 会关掉连接）。这里阻塞直到收到中断信号。
	go func() {
		if err := node.Listen(ctx, entryRelay); err != nil {
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
// index 非空时先经 index bootstrap 就近选定入口 relay; 否则直连 relayAddr。
func runConnect(relayAddr, index, target string, rounds int, msgPrefix, keyFile string, connectTimeoutSec int) {
	if len(target) != 64 {
		fmt.Printf("无效的 target NodeID 长度: %d (应为64位hex)\n", len(target))
		os.Exit(1)
	}
	privKey, err := loadKey(keyFile)
	if err != nil {
		fmt.Printf("加载私钥失败: %v\n", err)
		os.Exit(1)
	}
	bootstrapAddr := relayAddr
	if index != "" {
		bootstrapAddr = index
	}
	node, err := natnode.NewNATNode(privKey, bootstrapAddr)
	if err != nil {
		fmt.Printf("创建节点失败: %v\n", err)
		os.Exit(1)
	}
	defer node.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	fmt.Printf("NAT 节点 ID: %s\n", node.ID())

	entryRelay := relayAddr
	if index != "" {
		entry, err := node.Bootstrap(ctx, index)
		if err != nil {
			fmt.Printf("bootstrap 失败: %v\n", err)
			os.Exit(1)
		}
		entryRelay = entry
	}
	// 必须启动 Listen：注册本节点到入口 relay 并运行节点连接机制（与进程内测试一致）。
	go func() { _ = node.Listen(ctx, entryRelay) }()

	fmt.Printf("注册到 relay: %s\n", entryRelay)
	time.Sleep(1 * time.Second)

	fmt.Printf("正在跨中继连接 target %s ...\n", target)
	connCtx, connCancel := context.WithTimeout(ctx, time.Duration(connectTimeoutSec)*time.Second)
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
		recvCtx, recvCancel := context.WithTimeout(ctx, time.Duration(connectTimeoutSec)*time.Second)
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
//
// 两级命令:
//
//	relay <listen> [peer]   启动中继节点并阻塞(Ctrl+C 退出)
//	node  <relayAddr> [key] 启动 NAT 节点并进入「聊天会话」, 支持手动收发消息
//	quit                    退出
//
// 进入 node 聊天会话后(详见 runChatNode):
//
//	-c <NodeId>     跨中继连接到目标节点
//	-q              断开当前活动连接
//	/list           列出已知邻居
//	/who            显示本节点 ID 与当前活动会话
//	/key            打印本节点私钥 hex
//	/save <path>    保存私钥到文件
//	/exit           关闭节点, 返回上一级
//	其他输入         作为消息发送给当前活动连接
func runInteractive() {
	fmt.Println("=== relaychat 交互模式 ===")
	fmt.Println("用法:")
	fmt.Println("  relay <listen> [peer]    启动中继节点, 可选与对端 relay 建链 (阻塞, Ctrl+C 退出)")
	fmt.Println("  node  <relayAddr> [key]  启动 NAT 节点并进入聊天会话 (手动收发消息)")
	fmt.Println("  quit                     退出")
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
			runRelay(listen, "", peer, "", "")
		case "node":
			addr := "127.0.0.1:9000"
			if len(fields) > 1 {
				addr = fields[1]
			}
			key := ""
			if len(fields) > 2 {
				key = fields[2]
			}
			runChatNode(addr, key, scanner)
		default:
			fmt.Printf("未知命令: %s\n", fields[0])
		}
	}
}

// chatSession 维护交互式聊天会话的状态：当前活动连接、各 peer 的接收协程标记。
type chatSession struct {
	node *natnode.NATNode

	mu         sync.Mutex
	activeConn p2pnode.Connection
	activePeer p2pnode.NodeID
	// receiveStarted 标记某 peer 是否已启动接收协程, 避免重复启动。
	receiveStarted map[p2pnode.NodeID]bool

	ctx    context.Context
	cancel context.CancelFunc
}

// runChatNode 启动一个 NAT 节点并进入聊天会话, 支持手动连接 / 收发 / 查看消息。
//
// scanner 复用上层 runInteractive 的标准输入扫描器, 避免与外层 REPL 抢输入。
// relayAddr 是要注册到的入口 relay; keyFile 可选, 用同一身份再次上线。
func runChatNode(relayAddr, keyFile string, scanner *bufio.Scanner) {
	privKey, err := loadKey(keyFile)
	if err != nil {
		fmt.Printf("加载私钥失败: %v\n", err)
		return
	}
	if privKey != nil {
		fmt.Printf("已从 %q 加载私钥, 恢复原节点身份\n", keyFile)
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

	// 入站连接回调: 显示来源, 自动设为活动会话并启动接收协程。
	node.OnConnection(func(conn p2pnode.Connection) {
		peer := conn.Peer()
		s.mu.Lock()
		s.activeConn = conn
		s.activePeer = peer.ID
		alreadyStarted := s.receiveStarted[peer.ID]
		s.receiveStarted[peer.ID] = true
		s.mu.Unlock()
		fmt.Printf("\n[入站连接] 来自 %s (已设为当前会话)\n> ", peer.ID)
		if !alreadyStarted {
			go s.receiveLoop(conn)
		}
	})

	fmt.Printf("本节点 ID: %s\n", node.ID())
	fmt.Printf("注册到 relay: %s\n", relayAddr)

	go func() {
		if err := node.Listen(ctx, relayAddr); err != nil && ctx.Err() == nil {
			fmt.Printf("\nListen 退出: %v\n", err)
		}
	}()
	time.Sleep(500 * time.Millisecond)

	printChatHelp()
	s.chatLoop(scanner)
}

// printChatHelp 打印聊天会话内可用命令。
func printChatHelp() {
	fmt.Println("\n可用命令:")
	fmt.Println("  -c <NodeId>   跨中继连接到目标节点 (经入口 relay 自动 FIND + 桥接)")
	fmt.Println("  -q            断开当前活动连接")
	fmt.Println("  /list         列出已知邻居")
	fmt.Println("  /who          显示本节点 ID 与当前活动会话")
	fmt.Println("  /key          打印本节点私钥 hex (妥善保管)")
	fmt.Println("  /save <path>  保存私钥到文件")
	fmt.Println("  /help         再次显示本帮助")
	fmt.Println("  /exit         关闭节点, 返回上一级")
	fmt.Println("  其他输入       作为消息发送给当前活动连接")
	fmt.Println()
}

// chatLoop 是聊天会话的命令循环, 直到 /exit 或输入结束。
func (s *chatSession) chatLoop(scanner *bufio.Scanner) {
	for {
		fmt.Print("> ")
		if !scanner.Scan() {
			s.shutdown()
			return
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		switch {
		case line == "/exit":
			s.shutdown()
			fmt.Printf("节点 %s 已关闭, 返回上一级\n", s.node.ID())
			return

		case line == "/help":
			printChatHelp()

		case line == "/who":
			s.mu.Lock()
			active := s.activePeer
			s.mu.Unlock()
			fmt.Printf("本节点 ID: %s\n", s.node.ID())
			if active == "" {
				fmt.Println("当前无活动会话")
			} else {
				fmt.Printf("当前活动会话: %s\n", active)
			}

		case line == "/key":
			fmt.Printf("私钥(hex): %s\n", s.node.ExportPrivateKeyHex())
			fmt.Println("提示: 持有该字符串等同于持有节点身份, 请妥善保管")

		case strings.HasPrefix(line, "/save"):
			parts := strings.Fields(line)
			if len(parts) < 2 {
				fmt.Println("用法: /save <path>")
				continue
			}
			if err := s.node.SavePrivateKey(parts[1]); err != nil {
				fmt.Printf("保存失败: %v\n", err)
				continue
			}
			fmt.Printf("私钥已保存到 %q (权限 0600)\n", parts[1])

		case line == "/list":
			neighbors := s.node.Neighbors()
			if len(neighbors) == 0 {
				fmt.Println("暂无已知邻居")
				continue
			}
			s.mu.Lock()
			active := s.activePeer
			s.mu.Unlock()
			fmt.Printf("已知邻居 (%d 个):\n", len(neighbors))
			for _, p := range neighbors {
				mark := " "
				if p.ID == active {
					mark = "*"
				}
				fmt.Printf(" %s %s  (%s)\n", mark, p.ID, p.LastSeen.Format("15:04:05"))
			}

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
			fmt.Printf("已断开与 %s 的连接\n", peer)

		case strings.HasPrefix(line, "-c "):
			s.handleConnect(p2pnode.NodeID(strings.TrimSpace(line[3:])))

		default:
			s.handleSend(line)
		}
	}
}

// handleConnect 跨中继连接到目标节点并设为当前活动会话。
func (s *chatSession) handleConnect(targetID p2pnode.NodeID) {
	if len(targetID) != 64 {
		fmt.Printf("无效的 NodeID 长度: %d (应为 64 位 hex)\n", len(targetID))
		return
	}
	if targetID == s.node.ID() {
		fmt.Println("不能连接自身")
		return
	}
	fmt.Printf("正在跨中继连接 %s ...\n", targetID)
	conn, err := s.node.Connect(s.ctx, targetID)
	if err != nil {
		fmt.Printf("连接失败: %v\n", err)
		return
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
}

// handleSend 把一行文本作为消息发给当前活动连接。
func (s *chatSession) handleSend(text string) {
	s.mu.Lock()
	conn := s.activeConn
	s.mu.Unlock()
	if conn == nil {
		fmt.Println("无活动连接, 请先用 -c <NodeId> 连接目标节点")
		return
	}
	msg := &p2pnode.Message{Type: p2pnode.MsgAppData, Payload: []byte(text)}
	if err := conn.Send(s.ctx, msg); err != nil {
		fmt.Printf("发送失败: %v\n", err)
	}
}

// receiveLoop 持续接收某连接的消息并打印, 直到连接断开。
func (s *chatSession) receiveLoop(conn p2pnode.Connection) {
	peerID := conn.Peer().ID
	for {
		msg, err := conn.Receive(s.ctx)
		if err != nil {
			if s.ctx.Err() != nil {
				return // 节点关闭, 静默退出
			}
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

// shutdown 关闭会话: 取消 ctx 并关闭节点。
func (s *chatSession) shutdown() {
	s.cancel()
	s.node.Close()
}
