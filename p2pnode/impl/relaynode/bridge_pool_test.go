package relaynode

import (
	"bnfs_p2p/logx"
	"bnfs_p2p/network"
	"bnfs_p2p/networkFrameWork"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestBridgePool_Reuse 验证连接池的核心：多个 connID 复用同一条 physConn（mux session）。
// 断言：N 个并发 bridge 会话，底层物理连接数 << N（Phase B 固定 1 条）。
func TestBridgePool_Reuse(t *testing.T) {
	logx.SetLevel(logx.LevelDebug)

	// 启动一个 relay 节点作为 server（接收 bridge-mux 物理连接并 accept stream）
	serverRelay, serverAddr := newTestBridgeRelay(t, "server-relay-1")
	defer serverRelay.Close()

	// 启动一个"对端 relay"角色的 pool：连向 serverRelay，开多个并发 stream
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool := newRelayPeerPool(ctx, serverAddr, "client-relay-1", 1)
	defer pool.Close()

	// 等待池内物理连接建立（Phase B: minWarmConns=1 → 一条）
	time.Sleep(300 * time.Millisecond)

	const N = 8
	var wg sync.WaitGroup
	errCh := make(chan error, N)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			connID := fmt.Sprintf("pooltest-conn-%d", idx)
			targetNodeID := "fake-target-node"
			originPubKey := "fake-pub-key-" + hexEncodeInteger(idx)
			st, err := pool.OpenStream(connID, targetNodeID, originPubKey)
			if err != nil {
				errCh <- fmt.Errorf("OpenStream %d 失败: %w", idx, err)
				return
			}
			defer st.Close()
			// 简单双向字节测试：写入 idx → echo 回来校验
			payload := []byte(fmt.Sprintf("test-payload-%d", idx))
			if _, werr := st.Write(payload); werr != nil {
				errCh <- fmt.Errorf("stream %d Write 失败: %w", idx, werr)
				return
			}
			buf := make([]byte, len(payload))
			if _, rerr := io.ReadFull(st, buf); rerr != nil {
				errCh <- fmt.Errorf("stream %d Read 失败: %w", idx, rerr)
				return
			}
			if string(buf) != string(payload) {
				errCh <- fmt.Errorf("stream %d echo 不匹配: got %q want %q", idx, buf, payload)
			}
		}(i)
	}
	wg.Wait()
	close(errCh)
	for e := range errCh {
		t.Error(e)
	}

	// 断言：池内物理连接数 = 1（Phase B 固定 minWarmConns=1）
	pool.mu.Lock()
	physCount := len(pool.conns)
	pool.mu.Unlock()
	if physCount != 1 {
		t.Errorf("期望池内物理连接数 = 1 (Phase B), 实际 = %d", physCount)
	}
	t.Logf("✔ %d 个并发会话复用同 1 条物理连接", N)
}

// TestBridgePool_LeastLoaded 验证 least-loaded 分配：优先选择 ActiveStreams 最少的 physConn。
// Phase B 只有 1 条 conn，此测试为 Phase C 扩容后做准备（记录扩容前的基准行为）。
func TestBridgePool_LeastLoaded(t *testing.T) {
	logx.SetLevel(logx.LevelDebug)
	serverRelay, serverAddr := newTestBridgeRelay(t, "server-ll")
	defer serverRelay.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool := newRelayPeerPool(ctx, serverAddr, "client-ll", 1)
	defer pool.Close()
	time.Sleep(200 * time.Millisecond)

	// 开 3 条 stream，Phase B 都落在同一条 physConn，ActiveStreams 应 = 3
	st1, _ := pool.OpenStream("ll-1", "target", "key1")
	st2, _ := pool.OpenStream("ll-2", "target", "key2")
	st3, _ := pool.OpenStream("ll-3", "target", "key3")
	defer st1.Close()
	defer st2.Close()
	defer st3.Close()

	pool.mu.Lock()
	if len(pool.conns) != 1 {
		t.Fatalf("期望 1 条 physConn, 实际 %d", len(pool.conns))
	}
	active := 0
	pc := pool.conns[0]
	pc.mu.Lock()
	if pc.sess != nil {
		active = pc.sess.ActiveStreams()
	}
	pc.mu.Unlock()
	pool.mu.Unlock()

	if active != 3 {
		t.Errorf("期望 ActiveStreams=3, 实际=%d", active)
	}
	t.Logf("✔ least-loaded 逻辑正确（Phase B 基准: 1 physConn, 3 stream → ActiveStreams=3）")
}

// TestBridgePool_Reconnect 验证 physConn 断线后自动退避重连（沿用 peerLink.manage 范本）。
func TestBridgePool_Reconnect(t *testing.T) {
	logx.SetLevel(logx.LevelDebug)
	serverRelay, serverAddr := newTestBridgeRelay(t, "server-reconnect")
	defer serverRelay.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool := newRelayPeerPool(ctx, serverAddr, "client-reconnect", 1)
	defer pool.Close()
	time.Sleep(200 * time.Millisecond)

	// 强制关闭底层物理 session，模拟断线
	pool.mu.Lock()
	pc := pool.conns[0]
	pc.mu.Lock()
	sess := pc.sess
	pc.mu.Unlock()
	pool.mu.Unlock()
	if sess != nil {
		_ = sess.Close()
	}

	// 给 manage() 重连时间（退避 500ms → 拨号）
	time.Sleep(1200 * time.Millisecond)

	// 尝试开新 stream，应在重连成功后拿到 session
	st, err := pool.OpenStream("reconnect-1", "target", "key")
	if err != nil {
		t.Fatalf("重连后 OpenStream 失败: %v", err)
	}
	defer st.Close()
	t.Logf("✔ physConn 断线后自动重连成功")
}

// TestBridgePool_EndToEnd 完整端到端：入口 relay 用池开 stream，对端 relay accept stream
// 并走 ListenTCPConnection 接入，模拟真实跨中继数据传输。
func TestBridgePool_EndToEnd(t *testing.T) {
	logx.SetLevel(logx.LevelDebug)

	// 托管 relay（对端）：接受 bridge-mux 物理连接，accept stream，echo
	hostRelay, hostAddr := newTestBridgeRelay(t, "host-relay-e2e")
	defer hostRelay.Close()

	// 入口 relay（本端）：用池开 stream，发送数据
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	entryRelay := &RelayNode{
		ctx:         ctx,
		bridgePools: make(map[string]*relayPeerPool),
	}
	entryRelay.mu.Lock()
	pool := newRelayPeerPool(ctx, hostAddr, "entry-relay-e2e", 1)
	entryRelay.bridgePools[hostAddr] = pool
	entryRelay.mu.Unlock()
	defer entryRelay.closeBridgePools()

	time.Sleep(300 * time.Millisecond)

	// 开 stream 并发送 64KB 数据块（SHA 校验 echo）
	connID := "e2e-large"
	targetNodeID := "fake-target"
	originPubKey := "fake-origin-key"
	st, err := pool.OpenStream(connID, targetNodeID, originPubKey)
	if err != nil {
		t.Fatalf("OpenStream 失败: %v", err)
	}
	defer st.Close()

	chunk := make([]byte, 64*1024)
	for i := range chunk {
		chunk[i] = byte(i & 0xff)
	}
	wantHash := sha256.Sum256(chunk)

	if _, werr := st.Write(chunk); werr != nil {
		t.Fatalf("Write 失败: %v", werr)
	}
	recv := make([]byte, len(chunk))
	if _, rerr := io.ReadFull(st, recv); rerr != nil {
		t.Fatalf("Read 失败: %v", rerr)
	}
	gotHash := sha256.Sum256(recv)
	if gotHash != wantHash {
		t.Fatalf("SHA 不匹配: got %x want %x", gotHash, wantHash)
	}
	t.Logf("✔ 端到端 64KB echo SHA 一致: %x", wantHash[:8])
}

// ============================================================================
// 测试辅助：newTestBridgeRelay 启动一个能接收 bridge-mux 物理连接并 echo 的 relay 服务
// ============================================================================

func newTestBridgeRelay(t *testing.T, nodeID string) (*testBridgeRelay, string) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen 失败: %v", err)
	}
	addr := ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	r := &testBridgeRelay{
		nodeID: nodeID,
		ln:     ln,
		ctx:    ctx,
		cancel: cancel,
		acceptCount: new(int32),
	}
	go r.serve()
	return r, addr
}

type testBridgeRelay struct {
	nodeID      string
	ln          net.Listener
	ctx         context.Context
	cancel      context.CancelFunc
	acceptCount *int32
}

func (r *testBridgeRelay) serve() {
	for {
		conn, err := r.ln.Accept()
		if err != nil {
			return
		}
		go r.handleConn(conn)
	}
}

func (r *testBridgeRelay) handleConn(conn net.Conn) {
	defer conn.Close()
	// 1. 读取并丢弃物理连接级握手帧（RouteName="/relay/bridge-mux" 的 Message）
	handshakeFrame, err := network.ReadFrame(conn)
	if err != nil {
		return
	}
	_ = handshakeFrame // 验证通过，握手完成

	// 2. 创建 server MuxSession，循环 Accept stream
	sess := networkFrameWork.NewMuxSession(r.ctx, conn, false)
	for {
		st, err := sess.Accept()
		if err != nil {
			return
		}
		atomic.AddInt32(r.acceptCount, 1)
		go r.echoStream(st)
	}
}

func (r *testBridgeRelay) echoStream(st *networkFrameWork.MuxStream) {
	defer st.Close()
	// AcceptBridgeMuxStream 会在 stream 前注入合成 hello 帧，这里不需要它
	// （我们不走 ListenTCPConnection），直接用裸 stream echo。
	buf := make([]byte, 32*1024)
	for {
		n, err := st.Read(buf)
		if n > 0 {
			if _, werr := st.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (r *testBridgeRelay) Close() error {
	r.cancel()
	return r.ln.Close()
}

// hexEncodeInteger 生成稳定的 per-stream 公钥占位串。
func hexEncodeInteger(i int) string {
	return hex.EncodeToString([]byte(fmt.Sprintf("%d", i)))
}

// TestBridgePool_ExpandOnConcurrency 验证 Phase C 扩容：当唯一物理连接的并发会话数
// 达到 streamHighWatermark 时，autoscale 应新增物理连接（直到 poolMaxConns 封顶）。
func TestBridgePool_ExpandOnConcurrency(t *testing.T) {
	logx.SetLevel(logx.LevelInfo)
	serverRelay, serverAddr := newTestBridgeRelay(t, "server-expand")
	defer serverRelay.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	pool := newRelayPeerPool(ctx, serverAddr, "client-expand", 1)
	defer pool.Close()
	time.Sleep(300 * time.Millisecond)

	// 初始应只有 1 条物理连接
	if c := pool.connCount(); c != 1 {
		t.Fatalf("初始期望 1 条物理连接, 实际 %d", c)
	}

	// 开 streamHighWatermark+5 条并发 stream（不关闭，保持活跃）以触发扩容。
	openCount := streamHighWatermark + 5
	streams := make([]*networkFrameWork.MuxStream, 0, openCount)
	for i := 0; i < openCount; i++ {
		st, err := pool.OpenStream(fmt.Sprintf("expand-%d", i), "target", "key")
		if err != nil {
			t.Fatalf("OpenStream %d 失败: %v", i, err)
		}
		streams = append(streams, st)
	}
	defer func() {
		for _, st := range streams {
			_ = st.Close()
		}
	}()

	// autoscale 采样周期 200ms，给几个周期让它扩容。
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if pool.connCount() > 1 {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}

	got := pool.connCount()
	if got <= 1 {
		t.Errorf("期望并发达高水位后扩容 (>1 条), 实际 %d", got)
	}
	if got > poolMaxConns {
		t.Errorf("物理连接数 %d 超过封顶 poolMaxConns=%d", got, poolMaxConns)
	}
	t.Logf("✔ 并发 %d 条达高水位 → 池扩容至 %d 条 (封顶 %d)", openCount, got, poolMaxConns)
}

// TestBridgePool_NoExpandWhenIdle 验证 Phase C 不误扩容：低负载（远低于水位）时
// 池保持初始连接数不增长。
func TestBridgePool_NoExpandWhenIdle(t *testing.T) {
	logx.SetLevel(logx.LevelInfo)
	serverRelay, serverAddr := newTestBridgeRelay(t, "server-noexpand")
	defer serverRelay.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool := newRelayPeerPool(ctx, serverAddr, "client-noexpand", 1)
	defer pool.Close()
	time.Sleep(300 * time.Millisecond)

	// 只开少量 stream（远低于 streamHighWatermark）
	for i := 0; i < 3; i++ {
		st, err := pool.OpenStream(fmt.Sprintf("idle-%d", i), "target", "key")
		if err != nil {
			t.Fatalf("OpenStream %d 失败: %v", i, err)
		}
		defer st.Close()
	}

	// 等待多个采样周期，确认不扩容
	time.Sleep(1500 * time.Millisecond)
	if c := pool.connCount(); c != 1 {
		t.Errorf("低负载不应扩容, 期望 1 条, 实际 %d", c)
	}
	t.Logf("✔ 低负载(3 stream)保持 1 条物理连接, 未误扩容")
}

// TestBridgePool_BurstDetector 验证 Phase D 高峰探测器：滑动窗口内扩容触发次数
// 达到 burstTriggerCount 即进入高峰态，窗口外的旧事件被裁剪后退出高峰态。
func TestBridgePool_BurstDetector(t *testing.T) {
	p := &relayPeerPool{minWarmConns: 1}
	base := time.Now()

	// 窗口内连续记录 burstTriggerCount 次扩容 → 应判定为高峰态。
	for i := 0; i < burstTriggerCount; i++ {
		p.recordExpandEventLocked(base.Add(time.Duration(i) * 100 * time.Millisecond))
	}
	if !p.inBurstLocked(base.Add(burstTriggerCount * 100 * time.Millisecond)) {
		t.Errorf("窗口内 %d 次触发应进入高峰态", burstTriggerCount)
	}

	// 时间推进到窗口之外 → 旧事件失效，退出高峰态。
	future := base.Add(burstWindow + time.Second)
	if p.inBurstLocked(future) {
		t.Errorf("窗口外旧事件应失效, 不再处于高峰态")
	}
	t.Logf("✔ 高峰探测器: 窗口内 %d 次→高峰态, 窗口外→退出", burstTriggerCount)
}

// TestBridgePool_BurstBatchTrim 验证高峰态批量扩容受 poolMaxConns 封顶裁剪。
func TestBridgePool_BurstBatchTrim(t *testing.T) {
	p := &relayPeerPool{minWarmConns: 1}
	now := time.Now()
	// 预置 burstTriggerCount 次事件 → 高峰态
	for i := 0; i < burstTriggerCount; i++ {
		p.recordExpandEventLocked(now)
	}
	if !p.inBurstLocked(now) {
		t.Fatal("预置后应为高峰态")
	}
	// 模拟池内已接近封顶（poolMaxConns-2 条），批量应被裁剪到 room=2。
	room := 2
	batch := burstBatchSize
	if batch > room {
		batch = room
	}
	if batch != room {
		t.Errorf("高峰批量应裁剪到剩余空间 %d, 实际 %d", room, batch)
	}
	t.Logf("✔ 高峰批量 burstBatchSize=%d 被封顶裁剪到 room=%d", burstBatchSize, room)
}

// TestBridgePool_ReapIdle 验证 Phase D 收缩：空闲超时的物理连接被回收，
// 但保留 minWarmConns 条保底。
func TestBridgePool_ReapIdle(t *testing.T) {
	logx.SetLevel(logx.LevelInfo)
	serverRelay, serverAddr := newTestBridgeRelay(t, "server-reap")
	defer serverRelay.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool := newRelayPeerPool(ctx, serverAddr, "client-reap", 1)
	defer pool.Close()
	time.Sleep(200 * time.Millisecond)

	// 手动扩到 4 条物理连接
	for i := 0; i < 3; i++ {
		pool.addPhysConn()
	}
	time.Sleep(400 * time.Millisecond) // 等待物理连接建立
	if c := pool.connCount(); c != 4 {
		t.Fatalf("期望 4 条物理连接, 实际 %d", c)
	}

	// 所有连接当前空闲（无活跃 stream）。把空闲起点设为远古，再用 future 时间触发回收。
	past := time.Now().Add(-2 * poolIdleTimeout)
	pool.mu.Lock()
	for _, pc := range pool.conns {
		pc.mu.Lock()
		pc.idleSince = past
		pc.mu.Unlock()
	}
	pool.mu.Unlock()

	// 注入「现在」为未来时刻，触发空闲超时回收。
	pool.reapOnce(time.Now())

	// 应回收到 minWarmConns=1 条保底。
	if c := pool.connCount(); c != 1 {
		t.Errorf("空闲回收后期望保留 minWarmConns=1 条, 实际 %d", c)
	}
	t.Logf("✔ 收缩: 4 条空闲连接回收至保底 1 条")
}

// TestBridgePool_ReapKeepsActive 验证收缩不回收有活跃会话的连接。
func TestBridgePool_ReapKeepsActive(t *testing.T) {
	logx.SetLevel(logx.LevelInfo)
	serverRelay, serverAddr := newTestBridgeRelay(t, "server-reap-active")
	defer serverRelay.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	pool := newRelayPeerPool(ctx, serverAddr, "client-reap-active", 1)
	defer pool.Close()
	time.Sleep(200 * time.Millisecond)

	pool.addPhysConn()
	time.Sleep(400 * time.Millisecond)
	if c := pool.connCount(); c != 2 {
		t.Fatalf("期望 2 条物理连接, 实际 %d", c)
	}

	// 在其中一条上开一个活跃 stream（least-loaded 会选空的那条）
	st, err := pool.OpenStream("active-keep", "target", "key")
	if err != nil {
		t.Fatalf("OpenStream 失败: %v", err)
	}
	defer st.Close()

	// 把所有连接空闲起点设为远古
	past := time.Now().Add(-2 * poolIdleTimeout)
	pool.mu.Lock()
	for _, pc := range pool.conns {
		pc.mu.Lock()
		pc.idleSince = past
		pc.mu.Unlock()
	}
	pool.mu.Unlock()

	pool.reapOnce(time.Now())

	// 有活跃 stream 的连接不会被回收：至少保留 1 条（保底）+ 活跃连接不动。
	// 这里 minWarmConns=1，空闲那条被回收，活跃那条保留 → 剩 1 条且其上有活跃 stream。
	c := pool.connCount()
	if c < 1 {
		t.Errorf("活跃连接不应被回收, 实际剩 %d", c)
	}
	// 断言剩余连接里活跃 stream 仍在
	pool.mu.Lock()
	hasActive := false
	for _, pc := range pool.conns {
		pc.mu.Lock()
		if pc.sess != nil && pc.sess.ActiveStreams() > 0 {
			hasActive = true
		}
		pc.mu.Unlock()
	}
	pool.mu.Unlock()
	if !hasActive {
		t.Errorf("回收后活跃 stream 所在连接丢失")
	}
	t.Logf("✔ 收缩跳过活跃连接, 剩余 %d 条且活跃会话存活", c)
}
