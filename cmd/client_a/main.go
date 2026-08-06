package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"

	"bnfs_p2p/logx"
	"github.com/google/uuid"
	"github.com/pion/ice/v3"
)

func main() {
	// 生成 256 位 (32 字节) 的 Node ID，这里用 UUID 模拟唯一标识，实际可用 sha256(rand)
	nodeID := uuid.New().String()
	fmt.Printf("Generated NodeID: %s\n", nodeID)

	// 连接中继服务器
	conn, err := net.Dial("tcp", "localhost:9000")
	if err != nil {
		logx.Errorf("Failed to connect to relay server: %v", err)
		os.Exit(1)
	}
	defer conn.Close()

	// 注册
	_, err = conn.Write([]byte(fmt.Sprintf("REGISTER %s\n", nodeID)))
	if err != nil {
		logx.Errorf("Failed to register: %v", err)
		os.Exit(1)
	}

	reader := bufio.NewReader(conn)
	response, _ := reader.ReadString('\n')
	fmt.Print("Server response: ", response)

	if !strings.HasPrefix(response, "OK") {
		logx.Errorf("Registration failed: response=%q", strings.TrimSpace(response))
		os.Exit(1)
	}

	fmt.Println("Waiting for messages from ClientB... (Press Ctrl+C to exit)")

	// 启动 ICE Agent (此处仅为框架展示，实际穿透需交换 Candidate)
	// 在简单中继模式下，我们直接通过 TCP 连接接收转发来的消息
	// 如果需要真正的 P2P，需在此处实现 OnConnectionStateChange 和 Candidate 交换

	agentConfig := &ice.AgentConfig{
		NetworkTypes: []ice.NetworkType{ice.NetworkTypeTCP4}, // 测试用
	}
	agent, err := ice.NewAgent(agentConfig)
	if err != nil {
		logx.Warnf("Failed to create ICE agent (normal in loopback test): %v", err)
	} else {
		defer agent.Close()
		fmt.Println("ICE Agent initialized (Ready for P2P negotiation)")
	}

	// 循环读取服务器转发的消息
	for {
		msg, err := reader.ReadString('\n')
		if err != nil {
			logx.Warnf("Connection lost: %v", err)
			break
		}
		fmt.Printf("Received: %s", msg)
	}
}
