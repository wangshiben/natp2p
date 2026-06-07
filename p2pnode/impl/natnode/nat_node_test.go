package natnode

import (
	"bnfs_p2p/networkFrameWork"
	"bnfs_p2p/p2pnode"
	"context"
	"sync"
	"testing"
	"time"
)

const testRelayAddr = "127.0.0.1:9000"

// startRelay 启动中转服务器并等待就绪，返回关闭函数。
func startRelay(t *testing.T) (relay *networkFrameWork.RelayStarter, closeRelay func()) {
	t.Helper()
	relay = networkFrameWork.NewRelayStarter(testRelayAddr)
	go relay.StartListen()
	// 等待 relay 监听就绪
	time.Sleep(300 * time.Millisecond)
	return relay, func() { relay.Close() }
}

// TestNATNode_Register 验证基础的中转注册功能。
func TestNATNode_Register(t *testing.T) {
	_, closeRelay := startRelay(t)
	defer closeRelay()

	node, err := NewNATNode(nil, testRelayAddr)
	if err != nil {
		t.Fatalf("创建节点失败: %v", err)
	}
	defer node.Close()

	// 验证 NodeID 格式（64 位 hex）
	nodeID := string(node.ID())
	if len(nodeID) != 64 {
		t.Fatalf("NodeID 长度应为 64, 实际 %d, value: %s", len(nodeID), nodeID)
	}
	t.Logf("节点 ID: %s", nodeID)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 启动 Listen（阻塞等待入站连接）
	listenErr := make(chan error, 1)
	go func() {
		listenErr <- node.Listen(ctx, testRelayAddr)
	}()

	// 等待注册完成
	time.Sleep(500 * time.Millisecond)

	// 验证已注册到 relay
	node.mu.RLock()
	count := len(node.registeredRelays)
	node.mu.RUnlock()
	if count != 1 {
		t.Errorf("应有 1 个已注册 relay, 实际 %d", count)
	}
	t.Log("注册成功")
}

// TestNATNode_TwoNodeCommunication 验证两个节点通过中转节点握手和通信。
func TestNATNode_TwoNodeCommunication(t *testing.T) {
	_, closeRelay := startRelay(t)
	defer closeRelay()

	// 创建两个节点
	nodeA, err := NewNATNode(nil, testRelayAddr)
	if err != nil {
		t.Fatalf("创建节点 A 失败: %v", err)
	}
	defer nodeA.Close()

	nodeB, err := NewNATNode(nil, testRelayAddr)
	if err != nil {
		t.Fatalf("创建节点 B 失败: %v", err)
	}
	defer nodeB.Close()

	t.Logf("节点 A ID: %s", nodeA.ID())
	t.Logf("节点 B ID: %s", nodeB.ID())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A 监听入站连接
	connAReady := make(chan p2pnode.Connection, 1)
	nodeA.OnConnection(func(conn p2pnode.Connection) {
		connAReady <- conn
	})

	go func() {
		if err := nodeA.Listen(ctx, testRelayAddr); err != nil {
			t.Logf("A Listen 退出: %v", err)
		}
	}()
	time.Sleep(300 * time.Millisecond)

	// B 连接 A
	connBtoA, err := nodeB.Connect(ctx, nodeA.ID())
	if err != nil {
		t.Fatalf("B 连接 A 失败: %v", err)
	}
	t.Log("B → A 连接建立")

	// 等待 A 侧连接就绪
	var connAtoB p2pnode.Connection
	select {
	case connAtoB = <-connAReady:
		t.Log("A 侧连接已就绪")
	case <-time.After(5 * time.Second):
		t.Fatal("等待 A 侧连接超时")
	}

	// 验证双端身份一致
	if connBtoA.Peer().ID != nodeA.ID() {
		t.Errorf("B 侧对端 ID 应为 %s, 实际 %s", nodeA.ID(), connBtoA.Peer().ID)
	}
	if connAtoB.Peer().ID != nodeB.ID() {
		t.Errorf("A 侧对端 ID 应为 %s, 实际 %s", nodeB.ID(), connAtoB.Peer().ID)
	}

	// B → A 发送消息
	testMsg := &p2pnode.Message{
		Type:    p2pnode.MsgAppData,
		Payload: []byte("Hello from B"),
	}
	if err := connBtoA.Send(ctx, testMsg); err != nil {
		t.Fatalf("B 发送消息失败: %v", err)
	}
	t.Log("B 已发送消息")

	// A 接收消息
	received, err := connAtoB.Receive(ctx)
	if err != nil {
		t.Fatalf("A 接收消息失败: %v", err)
	}
	if string(received.Payload) != "Hello from B" {
		t.Errorf("消息内容不匹配: 期望 'Hello from B', 实际 '%s'", string(received.Payload))
	}
	t.Logf("A 收到消息: %s", string(received.Payload))

	// A → B 回复消息
	replyMsg := &p2pnode.Message{
		Type:    p2pnode.MsgAppData,
		Payload: []byte("Hello from A"),
	}
	if err := connAtoB.Send(ctx, replyMsg); err != nil {
		t.Fatalf("A 发送回复失败: %v", err)
	}
	t.Log("A 已发送回复")

	// B 接收回复
	receivedReply, err := connBtoA.Receive(ctx)
	if err != nil {
		t.Fatalf("B 接收回复失败: %v", err)
	}
	if string(receivedReply.Payload) != "Hello from A" {
		t.Errorf("回复内容不匹配: 期望 'Hello from A', 实际 '%s'", string(receivedReply.Payload))
	}
	t.Logf("B 收到回复: %s", string(receivedReply.Payload))
}

// TestNATNode_ThreeNodeDiscovery 验证三个节点通过中转节点相互查找与通信。
func TestNATNode_ThreeNodeDiscovery(t *testing.T) {
	_, closeRelay := startRelay(t)
	defer closeRelay()

	// 创建三个节点
	nodeA, _ := NewNATNode(nil, testRelayAddr)
	nodeB, _ := NewNATNode(nil, testRelayAddr)
	nodeC, _ := NewNATNode(nil, testRelayAddr)
	defer nodeA.Close()
	defer nodeB.Close()
	defer nodeC.Close()

	t.Logf("节点 A: %s", nodeA.ID())
	t.Logf("节点 B: %s", nodeB.ID())
	t.Logf("节点 C: %s", nodeC.ID())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 为每个节点设置 OnConnection 回调
	connA := make(chan p2pnode.Connection, 1)
	connB := make(chan p2pnode.Connection, 1)
	connC := make(chan p2pnode.Connection, 1)
	nodeA.OnConnection(func(c p2pnode.Connection) { connA <- c })
	nodeB.OnConnection(func(c p2pnode.Connection) { connB <- c })
	nodeC.OnConnection(func(c p2pnode.Connection) { connC <- c })

	// 三个节点同时启动 Listen
	var wg sync.WaitGroup
	for _, node := range []*NATNode{nodeA, nodeB, nodeC} {
		wg.Add(1)
		go func(n *NATNode) {
			defer wg.Done()
			n.Listen(ctx, testRelayAddr)
		}(node)
	}
	time.Sleep(500 * time.Millisecond)

	// 建立环形拓扑: B→A, C→B, A→C
	t.Log("=== 建立连接: B → A ===")
	connBtoA, err := nodeB.Connect(ctx, nodeA.ID())
	if err != nil {
		t.Fatalf("B 连接 A 失败: %v", err)
	}
	<-connA // 等待 A 收到入站连接
	t.Log("B → A 已连接")

	t.Log("=== 建立连接: C → B ===")
	connCtoB, err := nodeC.Connect(ctx, nodeB.ID())
	if err != nil {
		t.Fatalf("C 连接 B 失败: %v", err)
	}
	<-connB
	t.Log("C → B 已连接")

	t.Log("=== 建立连接: A → C ===")
	connAtoC, err := nodeA.Connect(ctx, nodeC.ID())
	if err != nil {
		t.Fatalf("A 连接 C 失败: %v", err)
	}
	<-connC
	t.Log("A → C 已连接")

	// ---------- 验证 Neighbors ----------
	neighborsA := nodeA.Neighbors()
	neighborsB := nodeB.Neighbors()
	neighborsC := nodeC.Neighbors()

	if len(neighborsA) < 2 {
		t.Errorf("节点 A 应有至少 2 个邻居, 实际 %d", len(neighborsA))
	}
	if len(neighborsB) < 2 {
		t.Errorf("节点 B 应有至少 2 个邻居, 实际 %d", len(neighborsB))
	}
	if len(neighborsC) < 2 {
		t.Errorf("节点 C 应有至少 2 个邻居, 实际 %d", len(neighborsC))
	}
	t.Logf("A 邻居: %d, B 邻居: %d, C 邻居: %d", len(neighborsA), len(neighborsB), len(neighborsC))

	// ---------- 验证 ClosestPeers ----------
	closestToA := nodeA.ClosestPeers(nodeA.ID(), 5)
	if len(closestToA) < 2 {
		t.Errorf("离 A 最近的节点应至少 2 个, 实际 %d", len(closestToA))
	}
	t.Logf("离 A 最近的节点: %d 个", len(closestToA))

	// ---------- 验证定向消息 (B→A, C→B, A→C) ----------
	// B → A
	msgBA := &p2pnode.Message{Type: p2pnode.MsgAppData, Payload: []byte("B to A")}
	if err := connBtoA.Send(ctx, msgBA); err != nil {
		t.Fatalf("B→A 发送失败: %v", err)
	}
	// 从 A 侧接收 (A 的入站连接来自 B)
	nodeA.mu.RLock()
	connAB := nodeA.conns[nodeB.ID()]
	nodeA.mu.RUnlock()
	if connAB == nil {
		t.Fatal("A 侧无 B 的连接")
	}
	recv, err := connAB.Receive(ctx)
	if err != nil {
		t.Fatalf("A 接收失败: %v", err)
	}
	if string(recv.Payload) != "B to A" {
		t.Errorf("A 收到内容不匹配: '%s'", string(recv.Payload))
	}
	t.Logf("B→A 消息验证通过: %s", string(recv.Payload))

	// C → B
	msgCB := &p2pnode.Message{Type: p2pnode.MsgAppData, Payload: []byte("C to B")}
	if err := connCtoB.Send(ctx, msgCB); err != nil {
		t.Fatalf("C→B 发送失败: %v", err)
	}
	nodeB.mu.RLock()
	connBC := nodeB.conns[nodeC.ID()]
	nodeB.mu.RUnlock()
	recv, err = connBC.Receive(ctx)
	if err != nil {
		t.Fatalf("B 接收失败: %v", err)
	}
	if string(recv.Payload) != "C to B" {
		t.Errorf("B 收到内容不匹配: '%s'", string(recv.Payload))
	}
	t.Logf("C→B 消息验证通过: %s", string(recv.Payload))

	// A → C
	msgAC := &p2pnode.Message{Type: p2pnode.MsgAppData, Payload: []byte("A to C")}
	if err := connAtoC.Send(ctx, msgAC); err != nil {
		t.Fatalf("A→C 发送失败: %v", err)
	}
	nodeC.mu.RLock()
	connCA := nodeC.conns[nodeA.ID()]
	nodeC.mu.RUnlock()
	recv, err = connCA.Receive(ctx)
	if err != nil {
		t.Fatalf("C 接收失败: %v", err)
	}
	if string(recv.Payload) != "A to C" {
		t.Errorf("C 收到内容不匹配: '%s'", string(recv.Payload))
	}
	t.Logf("A→C 消息验证通过: %s", string(recv.Payload))

	// ---------- 验证 Broadcast ----------
	t.Log("=== 测试广播: A → 所有邻居 ===")
	broadcastMsg := &p2pnode.Message{
		Type:    p2pnode.MsgBroadcast,
		TTL:     3,
		Payload: []byte("broadcast from A"),
	}
	if err := nodeA.Broadcast(ctx, broadcastMsg); err != nil {
		t.Fatalf("A 广播失败: %v", err)
	}

	// B 应收到广播（经 B↔A 的连接）
	recvB, err := connBtoA.Receive(ctx)
	if err != nil {
		t.Fatalf("B 接收广播失败: %v", err)
	}
	if string(recvB.Payload) != "broadcast from A" {
		t.Errorf("B 广播内容不匹配: '%s'", string(recvB.Payload))
	}
	t.Logf("B 收到广播: %s", string(recvB.Payload))

	// C 也应收到广播（经 C↔A 的连接）
	recvC, err := connCA.Receive(ctx)
	if err != nil {
		t.Fatalf("C 接收广播失败: %v", err)
	}
	if string(recvC.Payload) != "broadcast from A" {
		t.Errorf("C 广播内容不匹配: '%s'", string(recvC.Payload))
	}
	t.Logf("C 收到广播: %s", string(recvC.Payload))

	t.Log("=== 三节点测试全部通过 ===")
}

// TestNATNode_Bidirectional 验证双向通信和闭包行为。
func TestNATNode_Bidirectional(t *testing.T) {
	_, closeRelay := startRelay(t)
	defer closeRelay()

	nodeA, _ := NewNATNode(nil, testRelayAddr)
	nodeB, _ := NewNATNode(nil, testRelayAddr)
	defer nodeA.Close()
	defer nodeB.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connReady := make(chan p2pnode.Connection, 1)
	nodeA.OnConnection(func(conn p2pnode.Connection) {
		connReady <- conn
	})

	go nodeA.Listen(ctx, testRelayAddr)
	time.Sleep(300 * time.Millisecond)

	connB, err := nodeB.Connect(ctx, nodeA.ID())
	if err != nil {
		t.Fatalf("B 连接 A 失败: %v", err)
	}
	connA := <-connReady

	// 并发双向通信
	const rounds = 10
	var wg sync.WaitGroup

	// B 发 → A 收
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			msg := &p2pnode.Message{
				Type:    p2pnode.MsgAppData,
				Payload: []byte{byte(i)},
			}
			if err := connB.Send(ctx, msg); err != nil {
				t.Errorf("B 发送第 %d 轮失败: %v", i, err)
				return
			}
		}
	}()

	// A 收
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			recv, err := connA.Receive(ctx)
			if err != nil {
				t.Errorf("A 接收第 %d 轮失败: %v", i, err)
				return
			}
			if len(recv.Payload) != 1 || recv.Payload[0] != byte(i) {
				t.Errorf("第 %d 轮内容不匹配", i)
			}
		}
	}()

	wg.Wait()
	t.Logf("双向 %d 轮通信完成", rounds)
}
