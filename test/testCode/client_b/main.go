package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"bnfs_p2p/logx"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: client_b <Target_Node_ID> <Message>")
		os.Exit(1)
	}

	targetNodeID := os.Args[1]
	message := "Hello from ClientB!"
	if len(os.Args) >= 3 {
		message = os.Args[2]
	}

	// 连接中继服务器
	conn, err := net.Dial("tcp", "localhost:9000")
	if err != nil {
		logx.Errorf("Failed to connect to relay server: %v", err)
		os.Exit(1)
	}
	defer conn.Close()

	// ClientB 也可以注册自己，或者仅作为临时发送者
	// 这里为了简单，我们注册一个临时的 ID
	tempID := "ClientB_Temp"
	_, err = conn.Write([]byte(fmt.Sprintf("REGISTER %s\n", tempID)))
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

	// 发送消息到指定的 NodeID
	sendCmd := fmt.Sprintf("SEND %s %s\n", targetNodeID, message)
	_, err = conn.Write([]byte(sendCmd))
	if err != nil {
		logx.Errorf("Failed to send message: %v", err)
		os.Exit(1)
	}

	fmt.Printf("Message sent to %s: %s\n", targetNodeID, message)

	// 等待可能的回复或确认
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		msg, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		fmt.Printf("Reply from server: %s", msg)
	}
}
