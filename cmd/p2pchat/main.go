// P2P 聊天控制台程序。
//
// 启动后选择模式:
//
//	relay <addr>                  启动中转服务器
//	node  <relayAddr> [keyFile]   启动 NAT 节点并加入指定 relay；
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
	"os"
	"strings"
	"sync"
	"time"

	"bnfs_p2p/networkFrameWork"
	"bnfs_p2p/p2pnode"
	"bnfs_p2p/p2pnode/impl/natnode"
)

func main() {
	fmt.Println("=== P2P 聊天 ===")
	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Println()
		fmt.Println("可用模式:")
		fmt.Println("  relay <addr>                启动中转服务器  (例: relay :9000)")
		fmt.Println("  node  <relayAddr> [keyFile] 启动 NAT 节点；keyFile 可选, 用同一身份再次上线")
		fmt.Println("  quit                        退出程序")
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
		case "relay":
			addr := ":9000"
			if len(fields) > 1 {
				addr = fields[1]
			}
			startRelay(addr)
		case "node":
			addr := "127.0.0.1:9000"
			if len(fields) > 1 {
				addr = fields[1]
			}
			keyFile := ""
			if len(fields) > 2 {
				keyFile = fields[2]
			}
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
	fmt.Printf("注册到 relay: %s\n", relayAddr)

	// 启动 Listen。
	go func() {
		if err := node.Listen(ctx, relayAddr); err != nil {
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

	scanner := bufio.NewScanner(os.Stdin)

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
			natNode, ok := node.(*natnode.NATNode)
			if !ok {
				fmt.Println("当前节点不支持导出私钥")
				continue
			}
			fmt.Printf("私钥(hex): %s\n", natNode.ExportPrivateKeyHex())
			fmt.Println("提示: 持有该字符串等同于持有节点身份, 请妥善保管")

		case strings.HasPrefix(line, "/save"):
			parts := strings.Fields(line)
			if len(parts) < 2 {
				fmt.Println("用法: /save <path>")
				continue
			}
			path := parts[1]
			natNode, ok := node.(*natnode.NATNode)
			if !ok {
				fmt.Println("当前节点不支持导出私钥")
				continue
			}
			if err := natNode.SavePrivateKey(path); err != nil {
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

// -- 中转服务器 --

func startRelay(addr string) {
	fmt.Printf("Relay 服务器已启动，监听 %s (按 Ctrl+C 退出)\n", addr)
	relay := networkFrameWork.NewRelayStarter(addr)
	relay.StartListen()
}
