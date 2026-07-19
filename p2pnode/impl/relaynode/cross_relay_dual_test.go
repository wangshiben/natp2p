package relaynode

import (
	"bnfs_p2p/crypoto"
	"bnfs_p2p/p2pnode"
	"bnfs_p2p/p2pnode/impl/natnode"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
	"testing"
	"time"
)

// 独立端口，避免与其它测试冲突。
const (
	kcpRelay1Addr     = "127.0.0.1:19601"
	kcpRelay2Addr     = "127.0.0.1:19602"
	tcpRelay1Addr     = "127.0.0.1:19603"
	tcpRelay2Addr     = "127.0.0.1:19604"
	restartRelay1Addr = "127.0.0.1:19605"
	restartRelay2Addr = "127.0.0.1:19606"
)

func TestCrossRelay_DualTCPColdStart(t *testing.T) {
	t.Setenv("BNFS_DISABLE_KCP", "1")
	relay1 := startRelay(t, tcpRelay1Addr, tcpRelay1Addr)
	defer relay1.Close()
	relay2 := startRelay(t, tcpRelay2Addr, tcpRelay2Addr)
	defer relay2.Close()

	relay1.ConnectPeer(tcpRelay2Addr)
	relay2.ConnectPeer(tcpRelay1Addr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server, err := natnode.NewNATNode(nil, tcpRelay2Addr)
	if err != nil {
		t.Fatalf("创建 TCP-only server 失败: %v", err)
	}
	defer server.Close()
	serverReady := make(chan p2pnode.Connection, 1)
	server.OnConnection(func(connection p2pnode.Connection) { serverReady <- connection })
	go func() { _ = server.Listen(ctx, tcpRelay2Addr) }()

	client, err := natnode.NewNATNode(nil, tcpRelay1Addr)
	if err != nil {
		t.Fatalf("创建 TCP-only client 失败: %v", err)
	}
	defer client.Close()
	go func() { _ = client.Listen(ctx, tcpRelay1Addr) }()

	time.Sleep(1500 * time.Millisecond)
	connectCtx, connectCancel := context.WithTimeout(ctx, 12*time.Second)
	defer connectCancel()
	clientConnection, err := client.Connect(connectCtx, server.ID())
	if err != nil {
		t.Fatalf("TCP-only 冷启动跨中继连接失败: %v", err)
	}

	var serverConnection p2pnode.Connection
	select {
	case serverConnection = <-serverReady:
	case <-time.After(8 * time.Second):
		t.Fatal("TCP-only server 未收到跨中继连接")
	}

	payload := []byte("cross-relay-dual-tcp-cold-start")
	if err := clientConnection.Send(ctx, &p2pnode.Message{Type: p2pnode.MsgAppData, Payload: payload}); err != nil {
		t.Fatalf("TCP-only client 发送失败: %v", err)
	}
	received, err := serverConnection.Receive(ctx)
	if err != nil {
		t.Fatalf("TCP-only server 接收失败: %v", err)
	}
	if string(received.Payload) != string(payload) {
		t.Fatalf("TCP-only 跨中继内容不一致: got=%q want=%q", received.Payload, payload)
	}
}

func TestCrossRelay_DualTCPColdRestartAfterKCPRegistration(t *testing.T) {
	t.Setenv("BNFS_DISABLE_KCP", "")
	relay1 := startRelay(t, restartRelay1Addr, restartRelay1Addr)
	defer relay1.Close()
	relay2 := startRelay(t, restartRelay2Addr, restartRelay2Addr)
	defer relay2.Close()
	relay1.ConnectPeer(restartRelay2Addr)
	relay2.ConnectPeer(restartRelay1Addr)

	serverKey, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatalf("生成稳定 server 身份失败: %v", err)
	}
	firstContext, firstCancel := context.WithCancel(context.Background())
	firstServer, err := natnode.NewNATNode(serverKey, restartRelay2Addr)
	if err != nil {
		t.Fatalf("创建首代 KCP server 失败: %v", err)
	}
	go func() { _ = firstServer.Listen(firstContext, restartRelay2Addr) }()
	time.Sleep(1200 * time.Millisecond)
	serverID := firstServer.ID()
	firstCancel()
	_ = firstServer.Close()

	t.Setenv("BNFS_DISABLE_KCP", "1")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	secondServer, err := natnode.NewNATNode(serverKey, restartRelay2Addr)
	if err != nil {
		t.Fatalf("创建第二代 TCP-only server 失败: %v", err)
	}
	defer secondServer.Close()
	serverReady := make(chan p2pnode.Connection, 1)
	secondServer.OnConnection(func(connection p2pnode.Connection) { serverReady <- connection })
	go func() { _ = secondServer.Listen(ctx, restartRelay2Addr) }()
	time.Sleep(1200 * time.Millisecond)

	t.Setenv("BNFS_DISABLE_KCP", "")
	client, err := natnode.NewNATNode(nil, restartRelay1Addr)
	if err != nil {
		t.Fatalf("创建跨中继 client 失败: %v", err)
	}
	defer client.Close()
	go func() { _ = client.Listen(ctx, restartRelay1Addr) }()
	time.Sleep(1200 * time.Millisecond)

	connectCtx, connectCancel := context.WithTimeout(ctx, 12*time.Second)
	defer connectCancel()
	clientConnection, err := client.Connect(connectCtx, serverID)
	if err != nil {
		t.Fatalf("KCP→双 TCP 冷重启后跨中继连接失败: %v", err)
	}
	defer clientConnection.Close()

	var serverConnection p2pnode.Connection
	select {
	case serverConnection = <-serverReady:
	case <-time.After(8 * time.Second):
		t.Fatal("第二代 TCP-only server 未收到跨中继连接")
	}

	payload := []byte("kcp-to-dual-tcp-cold-restart")
	if err := clientConnection.Send(ctx, &p2pnode.Message{Type: p2pnode.MsgAppData, Payload: payload}); err != nil {
		t.Fatalf("冷重启后 client 发送失败: %v", err)
	}
	received, err := serverConnection.Receive(ctx)
	if err != nil {
		t.Fatalf("冷重启后 server 接收失败: %v", err)
	}
	if string(received.Payload) != string(payload) {
		t.Fatalf("冷重启跨中继内容不一致: got=%q want=%q", received.Payload, payload)
	}
}

// TestCrossRelay_DualLeg_LargeTransfer 验证 dual(KCP+TCP) 拨号下跨中继桥接能否
// 完整传输大流量数据。这是路线 B 的可行性前提：KCP leg 经裸字节 peerConn 跨中继是否走通。
//
// 拓扑：local1 → relay1, local2 → relay2, relay1<->relay2 控制链路。
// local1 dual 拨号连 local2（跨中继）。双向各传 N 条大消息，校验 SHA256 完整性。
func TestCrossRelay_DualLeg_LargeTransfer(t *testing.T) {
	relay1 := startRelay(t, kcpRelay1Addr, kcpRelay1Addr)
	defer relay1.Close()
	relay2 := startRelay(t, kcpRelay2Addr, kcpRelay2Addr)
	defer relay2.Close()

	relay2.ConnectPeer(kcpRelay1Addr)
	relay1.ConnectPeer(kcpRelay2Addr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	local2, err := natnode.NewNATNode(nil, kcpRelay2Addr)
	if err != nil {
		t.Fatalf("创建 local2 失败: %v", err)
	}
	defer local2.Close()

	conn2Ready := make(chan p2pnode.Connection, 1)
	local2.OnConnection(func(c p2pnode.Connection) { conn2Ready <- c })
	go func() { _ = local2.Listen(ctx, kcpRelay2Addr) }()

	local1, err := natnode.NewNATNode(nil, kcpRelay1Addr)
	if err != nil {
		t.Fatalf("创建 local1 失败: %v", err)
	}
	defer local1.Close()
	go func() { _ = local1.Listen(ctx, kcpRelay1Addr) }()

	time.Sleep(1500 * time.Millisecond)

	connCtx, connCancel := context.WithTimeout(ctx, 12*time.Second)
	defer connCancel()
	dialStart := time.Now()
	conn1, err := local1.Connect(connCtx, local2.ID())
	if err != nil {
		t.Fatalf("local1 dual 跨中继连接 local2 失败: %v", err)
	}
	dialDur := time.Since(dialStart)
	t.Logf("local1 → local2 dual 跨中继连接已建立 (耗时 %v)", dialDur)
	// KCP 先到的正常路径不应触发 TCP 等待窗口(400ms)。若耗时明显超过窗口,
	// 说明 KCP 优先逻辑未生效、走了 TCP 兜底慢路径。
	if dialDur > 2*time.Second {
		t.Logf("⚠️  建连耗时 %v 偏高, 可能未走 KCP 优先路径", dialDur)
	}

	var conn2 p2pnode.Connection
	select {
	case conn2 = <-conn2Ready:
	case <-time.After(8 * time.Second):
		t.Fatal("local2 侧入站连接超时")
	}

	// 大流量传输：每条消息 64KB，传 16 条 = 1MB 单向。
	const msgSize = 64 * 1024
	const msgCount = 16
	payload := make([]byte, msgSize)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	wantSum := sha256.Sum256(payload)
	wantHex := hex.EncodeToString(wantSum[:])

	var wg sync.WaitGroup
	wg.Add(2)
	errCh := make(chan error, 2)

	// local2 侧：回显收到的每条消息（校验后原样发回）。
	go func() {
		defer wg.Done()
		for i := 0; i < msgCount; i++ {
			recv, err := conn2.Receive(ctx)
			if err != nil {
				errCh <- fmt.Errorf("local2 接收第 %d 条失败: %w", i, err)
				return
			}
			sum := sha256.Sum256(recv.Payload)
			if hex.EncodeToString(sum[:]) != wantHex {
				errCh <- fmt.Errorf("local2 第 %d 条数据损坏: 大小=%d", i, len(recv.Payload))
				return
			}
			if err := conn2.Send(ctx, &p2pnode.Message{Type: p2pnode.MsgAppData, Payload: recv.Payload}); err != nil {
				errCh <- fmt.Errorf("local2 回显第 %d 条失败: %w", i, err)
				return
			}
		}
	}()

	// local1 侧：发 msgCount 条，并校验回显完整性。
	go func() {
		defer wg.Done()
		for i := 0; i < msgCount; i++ {
			if err := conn1.Send(ctx, &p2pnode.Message{Type: p2pnode.MsgAppData, Payload: payload}); err != nil {
				errCh <- fmt.Errorf("local1 发送第 %d 条失败: %w", i, err)
				return
			}
			recv, err := conn1.Receive(ctx)
			if err != nil {
				errCh <- fmt.Errorf("local1 接收回显第 %d 条失败: %w", i, err)
				return
			}
			sum := sha256.Sum256(recv.Payload)
			if hex.EncodeToString(sum[:]) != wantHex {
				errCh <- fmt.Errorf("local1 回显第 %d 条数据损坏: 大小=%d", i, len(recv.Payload))
				return
			}
		}
	}()

	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	select {
	case <-done:
		select {
		case err := <-errCh:
			t.Fatalf("传输错误: %v", err)
		default:
		}
		t.Logf("✅ dual 跨中继大流量传输成功: %d 条 × %dKB 双向, SHA256 全部一致", msgCount, msgSize/1024)
	case err := <-errCh:
		t.Fatalf("传输错误: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("大流量传输超时（30s）——可能 KCP 跨中继不通或竞态卡死")
	}
}
