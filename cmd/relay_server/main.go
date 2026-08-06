package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"bnfs_p2p/logx"
	"github.com/pion/ice/v3"
)

// NodeSession 代表一个连接到中继服务器的客户端会话
type NodeSession struct {
	NodeID string
	Conn   net.Conn
	Agent  *ice.Agent
	Mu     sync.Mutex
}

var (
	sessions = make(map[string]*NodeSession)
	mu       sync.RWMutex
)

func main() {
	listener, err := net.Listen("tcp", ":9000")
	if err != nil {
		logx.Errorf("Failed to start relay server: %v", err)
		os.Exit(1)
	}
	fmt.Println("Relay Server started on :9000")

	for {
		conn, err := listener.Accept()
		if err != nil {
			logx.Warnf("Failed to accept connection: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	var nodeID string
	var _ *ice.Agent

	// 简单的协议握手：第一行必须是 "REGISTER <NODE_ID>"
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(strings.TrimSpace(line))
	if len(parts) != 2 || parts[0] != "REGISTER" {
		conn.Write([]byte("ERROR: Invalid registration format\n"))
		return
	}
	nodeID = parts[1]
	fmt.Printf("Client registered with NodeID: %s\n", nodeID)

	// 注册会话
	mu.Lock()
	if _, exists := sessions[nodeID]; exists {
		mu.Unlock()
		conn.Write([]byte("ERROR: NodeID already exists\n"))
		return
	}
	session := &NodeSession{NodeID: nodeID, Conn: conn}
	sessions[nodeID] = session
	mu.Unlock()

	conn.Write([]byte(fmt.Sprintf("OK: Registered as %s\n", nodeID)))

	// 在此处简化处理：实际生产中需要交换 ICE Candidates
	// 为了演示中继流量，我们假设连接建立后，直接转发后续消息
	// 如果涉及复杂的 ICE 协商，需要解析 SDP 和 Candidate 并通过信令转发

	// 监听来自该客户端的消息并转发
	for {
		msg, err := reader.ReadString('\n')
		if err != nil {
			fmt.Printf("Client %s disconnected\n", nodeID)
			break
		}

		msg = strings.TrimSpace(msg)
		if msg == "" {
			continue
		}

		// 协议格式：SEND <TARGET_NODE_ID> <MESSAGE>
		fields := strings.SplitN(msg, " ", 3)
		if len(fields) < 3 || fields[0] != "SEND" {
			// 非转发消息，可能是内部信令，此处暂不处理或打印
			fmt.Printf("Received from %s: %s\n", nodeID, msg)
			continue
		}

		targetID := fields[1]
		payload := fields[2]

		mu.RLock()
		targetSession, exists := sessions[targetID]
		mu.RUnlock()

		if !exists {
			conn.Write([]byte(fmt.Sprintf("ERROR: Target %s not found\n", targetID)))
			continue
		}

		// 转发消息
		forwardMsg := fmt.Sprintf("FROM %s: %s\n", nodeID, payload)
		_, err = targetSession.Conn.Write([]byte(forwardMsg))
		if err != nil {
			logx.Warnf("Failed to forward message to %s: %v", targetID, err)
		} else {
			fmt.Printf("Forwarded message from %s to %s\n", nodeID, targetID)
		}
	}

	// 清理会话
	mu.Lock()
	delete(sessions, nodeID)
	mu.Unlock()
}
