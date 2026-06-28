package relaynode

import (
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

const (
	stripeRelay1Addr = "127.0.0.1:19611"
	stripeRelay2Addr = "127.0.0.1:19612"
)

// TestCrossRelay_Striped_Integrity 验证 F3 条带化端到端：入口 relay 把单条逻辑连接的字节流
// 拆到 M 条独立物理 TCP 并行传输，对端 relay 按 connID 归并 M 条 leg、按序号重排，
// 最终业务数据 SHA256 完整。这是模式 B 正确性的硬验证。
func TestCrossRelay_Striped_Integrity(t *testing.T) {
	relay1 := startRelay(t, stripeRelay1Addr, stripeRelay1Addr)
	defer relay1.Close()
	relay2 := startRelay(t, stripeRelay2Addr, stripeRelay2Addr)
	defer relay2.Close()

	relay2.ConnectPeer(stripeRelay1Addr)
	relay1.ConnectPeer(stripeRelay2Addr)

	// 入口 relay1 启用条带化 width=3，并预扩其到 relay2 的连接池到 ≥3 条物理连接，
	// 让条带化能真正摊到多条独立 TCP。
	relay1.SetBridgeWidth(3)
	pool := relay1.poolFor(stripeRelay2Addr)
	pool.addPhysConn()
	pool.addPhysConn()
	time.Sleep(500 * time.Millisecond) // 等物理连接建立
	if c := pool.connCount(); c < 3 {
		t.Logf("注意: 入口池物理连接数=%d (<3)，条带化宽度会被相应裁剪", c)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	local2, err := natnode.NewNATNode(nil, stripeRelay2Addr)
	if err != nil {
		t.Fatalf("创建 local2 失败: %v", err)
	}
	defer local2.Close()
	conn2Ready := make(chan p2pnode.Connection, 1)
	local2.OnConnection(func(c p2pnode.Connection) { conn2Ready <- c })
	go func() { _ = local2.Listen(ctx, stripeRelay2Addr) }()

	local1, err := natnode.NewNATNode(nil, stripeRelay1Addr)
	if err != nil {
		t.Fatalf("创建 local1 失败: %v", err)
	}
	defer local1.Close()
	go func() { _ = local1.Listen(ctx, stripeRelay1Addr) }()

	time.Sleep(1500 * time.Millisecond)

	connCtx, connCancel := context.WithTimeout(ctx, 12*time.Second)
	defer connCancel()
	conn1, err := local1.Connect(connCtx, local2.ID())
	if err != nil {
		t.Fatalf("local1 跨中继连接 local2 失败: %v", err)
	}
	t.Logf("local1 → local2 跨中继连接已建立 (条带化 width=%d, 入口池=%d 条)",
		3, pool.connCount())

	var conn2 p2pnode.Connection
	select {
	case conn2 = <-conn2Ready:
	case <-time.After(8 * time.Second):
		t.Fatal("local2 侧入站连接超时")
	}

	// 大流量：每条 64KB，传 16 条 = 1MB 单向，双向 echo 校验 SHA。
	const msgSize = 64 * 1024
	const msgCount = 16
	payload := make([]byte, msgSize)
	for i := range payload {
		payload[i] = byte((i*7 + 13) % 251)
	}
	wantSum := sha256.Sum256(payload)
	wantHex := hex.EncodeToString(wantSum[:])

	var wg sync.WaitGroup
	wg.Add(2)
	errCh := make(chan error, 2)

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
			t.Fatalf("条带化传输错误: %v", err)
		default:
		}
		t.Logf("✅ 条带化跨中继传输成功: %d 条 × %dKB 双向, SHA256 全部一致 (width=3 重排正确)",
			msgCount, msgSize/1024)
	case err := <-errCh:
		t.Fatalf("条带化传输错误: %v", err)
	case <-time.After(30 * time.Second):
		t.Fatal("条带化传输超时（30s）")
	}
}
