package relaynode

import (
	"bnfs_p2p/p2pnode"
	"bnfs_p2p/p2pnode/impl/natnode"
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRelayNodeUnregisterRemovesHostedIndexes(t *testing.T) {
	relay, err := NewRelayNode(nil, "127.0.0.1:0", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("创建 RelayNode 失败: %v", err)
	}
	defer relay.Close()

	nodeID := strings.Repeat("a", 64)
	relay.onRegister(nodeID, "192.0.2.10:32000")
	if len(relay.HostedNatNodes()) != 1 {
		t.Fatalf("注册后托管节点数 = %d, want 1", len(relay.HostedNatNodes()))
	}
	relay.mu.RLock()
	remoteAddr := relay.hostedNatAddr[nodeID]
	relay.mu.RUnlock()
	if remoteAddr == "" {
		t.Fatal("注册后缺少托管来源地址")
	}

	relay.onUnregister(nodeID)
	if len(relay.HostedNatNodes()) != 0 {
		t.Fatalf("注销后托管节点数 = %d, want 0", len(relay.HostedNatNodes()))
	}
	relay.mu.RLock()
	_, retained := relay.hostedNatAddr[nodeID]
	relay.mu.RUnlock()
	if retained {
		t.Fatal("注销后仍保留托管来源地址")
	}
}

// 端口分配：两台 relay 各监听一个本地端口。
const (
	relay1Addr = "127.0.0.1:19501"
	relay2Addr = "127.0.0.1:19502"
)

// startRelay 启动一个 RelayNode 并等待监听就绪。
func startRelay(t *testing.T, listen, public string) *RelayNode {
	t.Helper()
	rn, err := NewRelayNode(nil, listen, public)
	if err != nil {
		t.Fatalf("创建 RelayNode 失败: %v", err)
	}
	go rn.Start()
	select {
	case <-rn.starter.Ready():
		return rn
	case <-rn.starter.Done():
		startErr := rn.starter.StartError()
		_ = rn.Close()
		t.Fatalf("启动 RelayNode %s 失败: %v", listen, startErr)
	case <-time.After(3 * time.Second):
		_ = rn.Close()
		t.Fatalf("等待 RelayNode %s 就绪超时", listen)
	}
	return nil
}

// TestRelayNode_CrossRelayBridge 验证跨中继查找 + 桥接 + 多轮端到端通信。
//
// 拓扑：local1 → relay1, local2 → relay2, relay2 → relay1（控制链路）。
// local1 连接 local2（relay1 本地未托管）→ relay1 经控制链路 FIND 到 relay2 → 跨中继桥接。
func TestRelayNode_CrossRelayBridge(t *testing.T) {
	relay1 := startRelay(t, relay1Addr, relay1Addr)
	defer relay1.Close()
	relay2 := startRelay(t, relay2Addr, relay2Addr)
	defer relay2.Close()

	// relay2 主动与 relay1 建立可重试控制链路。
	relay2.ConnectPeer(relay1Addr)
	relay1.ConnectPeer(relay2Addr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// local2 注册到 relay2 并监听入站连接。
	local2, err := natnode.NewNATNode(nil, relay2Addr)
	if err != nil {
		t.Fatalf("创建 local2 失败: %v", err)
	}
	defer local2.Close()

	conn2Ready := make(chan p2pnode.Connection, 1)
	local2.OnConnection(func(c p2pnode.Connection) { conn2Ready <- c })
	go func() { _ = local2.Listen(ctx, relay2Addr) }()

	// local1 注册到 relay1。
	local1, err := natnode.NewNATNode(nil, relay1Addr)
	if err != nil {
		t.Fatalf("创建 local1 失败: %v", err)
	}
	defer local1.Close()
	go func() { _ = local1.Listen(ctx, relay1Addr) }()

	// 等待注册 + 控制链路就绪。
	time.Sleep(1500 * time.Millisecond)

	// 校验 DHT 区分：relay1 应已通过 HELLO 获知 relay2。
	if len(relay1.RelayNeighbors()) == 0 && len(relay2.RelayNeighbors()) == 0 {
		t.Fatalf("控制链路未交换 relay 身份: relay1 邻居=%d relay2 邻居=%d",
			len(relay1.RelayNeighbors()), len(relay2.RelayNeighbors()))
	}
	t.Logf("relay1 relay邻居=%d, relay2 relay邻居=%d", len(relay1.RelayNeighbors()), len(relay2.RelayNeighbors()))
	t.Logf("relay2 托管 nat 节点=%d", len(relay2.HostedNatNodes()))

	// local1 连接 local2（跨中继）。
	connCtx, connCancel := context.WithTimeout(ctx, 10*time.Second)
	defer connCancel()
	conn1, err := local1.Connect(connCtx, local2.ID())
	if err != nil {
		t.Fatalf("local1 跨中继连接 local2 失败: %v", err)
	}
	t.Log("local1 → local2 跨中继连接已建立")

	var conn2 p2pnode.Connection
	select {
	case conn2 = <-conn2Ready:
	case <-time.After(8 * time.Second):
		t.Fatal("local2 侧入站连接超时")
	}

	if conn1.Peer().ID != local2.ID() {
		t.Errorf("local1 侧对端应为 local2: %s", conn1.Peer().ID)
	}
	if conn2.Peer().ID != local1.ID() {
		t.Errorf("local2 侧对端应为 local1: %s", conn2.Peer().ID)
	}

	// 2-3 轮双向通信。
	const rounds = 3
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			msg := &p2pnode.Message{Type: p2pnode.MsgAppData, Payload: []byte(fmt.Sprintf("ping-%d", i))}
			if err := conn1.Send(ctx, msg); err != nil {
				t.Errorf("local1 发送第 %d 轮失败: %v", i, err)
				return
			}
			recv, err := conn1.Receive(ctx)
			if err != nil {
				t.Errorf("local1 接收第 %d 轮回复失败: %v", i, err)
				return
			}
			want := fmt.Sprintf("pong-%d", i)
			if string(recv.Payload) != want {
				t.Errorf("local1 第 %d 轮回复不匹配: 期望 %q 得到 %q", i, want, string(recv.Payload))
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < rounds; i++ {
			recv, err := conn2.Receive(ctx)
			if err != nil {
				t.Errorf("local2 接收第 %d 轮失败: %v", i, err)
				return
			}
			want := fmt.Sprintf("ping-%d", i)
			if string(recv.Payload) != want {
				t.Errorf("local2 第 %d 轮内容不匹配: 期望 %q 得到 %q", i, want, string(recv.Payload))
			}
			reply := &p2pnode.Message{Type: p2pnode.MsgAppData, Payload: []byte(fmt.Sprintf("pong-%d", i))}
			if err := conn2.Send(ctx, reply); err != nil {
				t.Errorf("local2 回复第 %d 轮失败: %v", i, err)
				return
			}
		}
	}()
	wg.Wait()
	t.Logf("跨中继 %d 轮双向通信完成", rounds)
}

// TestRelayNode_FindMiss 验证：目标 nat 节点无任何 relay 托管时, 连接返回错误（需求 3）。
func TestRelayNode_FindMiss(t *testing.T) {
	relay1 := startRelay(t, "127.0.0.1:19503", "127.0.0.1:19503")
	defer relay1.Close()
	relay2 := startRelay(t, "127.0.0.1:19504", "127.0.0.1:19504")
	defer relay2.Close()
	relay1.ConnectPeer("127.0.0.1:19504")
	relay2.ConnectPeer("127.0.0.1:19503")
	time.Sleep(1 * time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	local1, err := natnode.NewNATNode(nil, "127.0.0.1:19503")
	if err != nil {
		t.Fatalf("创建 local1 失败: %v", err)
	}
	defer local1.Close()
	go func() { _ = local1.Listen(ctx, "127.0.0.1:19503") }()
	time.Sleep(500 * time.Millisecond)

	// 连接一个根本不存在的随机 nat 节点。
	ghost, _ := natnode.NewNATNode(nil, "127.0.0.1:19503")
	defer ghost.Close()

	connCtx, connCancel := context.WithTimeout(ctx, 8*time.Second)
	defer connCancel()
	_, err = local1.Connect(connCtx, ghost.ID())
	if err == nil {
		t.Fatal("连接不存在的 nat 节点应当返回错误")
	}
	t.Logf("符合预期: 连接未托管节点返回错误: %v", err)
}
