package networkFrameWork

import (
	"bnfs_p2p/network"
	"net"
	"strings"
	"testing"
	"time"
)

// startTCPOnlyRelayWithCover 启动只监听 TCP(不监听 KCP/UDP) 的 relay, 返回地址与底层 cover。
// 用于模拟"运营商高峰期掐 UDP, KCP 不通": client dual 拨号时 KCP 握手超时,
// 触发 KCP 槽位改用 TCP 备路 leg。
func startTCPOnlyRelayWithCover(t *testing.T) (addr string, cover *TransportCover, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动 TCP-only relay 失败: %v", err)
	}
	transport := NewTransportCover()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if err := transport.ListenTCPConnection(c); err != nil &&
					!strings.Contains(err.Error(), "use of closed network connection") {
					// 忽略测试中连接关闭的正常错误
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), transport, func() { _ = ln.Close() }
}

// TestDualDial_KCPBlocked_FallbackToSecondTCP 验证 KCP(UDP) 不通时,
// dual 拨号不退化成单 leg, 而是在 KCP 槽位补一条 TCP, 组成双 TCP leg(failover 冗余)。
func TestDualDial_KCPBlocked_FallbackToSecondTCP(t *testing.T) {
	relayAddr, cover, stop := startTCPOnlyRelayWithCover(t)
	defer stop()

	// server 端注册 target, 让 relay 持有其 StreamGroup, 否则 client 连接会被 relay 关闭。
	serverID, err := newRelayTestIdentity("dualtcp-server")
	if err != nil {
		t.Fatalf("创建 server 身份失败: %v", err)
	}
	serverStream, err := registerRelayTCPOnly(serverID, relayAddr)
	if err != nil {
		t.Fatalf("server 注册 relay 失败: %v", err)
	}
	defer serverStream.Close()
	if err := waitForRelayGroup(cover, serverID.nodeID, 3*time.Second); err != nil {
		t.Fatalf("等待 server StreamGroup 就绪超时: %v", err)
	}

	// client dual 拨号 target(=server)。relay 只监听 TCP, KCP 握手必然超时(dialHandshakeTimeout)。
	connID := "dualtcp-failover-test"
	header := &network.Header{NodeId: serverID.nodeID, NodeIdVersion: 1, ConnectionId: connID}
	body := &network.Message{Header: header, Payload: []byte("clientpubkeyhex")}

	start := time.Now()
	stream, err := clientStream(body, relayAddr, serverID.nodeID, connID, true)
	dur := time.Since(start)
	if err != nil {
		t.Fatalf("dual 拨号失败(期望降级为双 TCP 成功): %v", err)
	}
	defer stream.Close()

	dual, ok := stream.(*DualStream)
	if !ok {
		t.Fatalf("期望返回 *DualStream, 实际 %T", stream)
	}

	// 断言 1: 应有两条 leg(没退化成单 leg)。
	dual.mu.RLock()
	legCount := len(dual.legs)
	tcpFamilyCount := 0
	var legIDs []streamTransport
	for id, entry := range dual.legs {
		legIDs = append(legIDs, id)
		if entry.family == streamTransportTCP {
			tcpFamilyCount++
		}
	}
	streams := make([]network.Stream, 0, len(dual.legs))
	for _, entry := range dual.legs {
		streams = append(streams, entry.stream)
	}
	dual.mu.RUnlock()

	if legCount != 2 {
		t.Errorf("应有 2 条 leg(双 TCP failover), 实际 %d 条: %v", legCount, legIDs)
	}

	// 断言 2: 两条 leg 都是 TCP 物理族(KCP 不通, 补的是第二条 TCP)。
	if tcpFamilyCount != 2 {
		t.Errorf("两条 leg 都应为 TCP 物理族, 实际 TCP 族 %d 条", tcpFamilyCount)
	}
	for _, s := range streams {
		if lt := LegTransport(s); lt != "tcp" {
			t.Errorf("leg 底层应为 tcp, 实际 =%q", lt)
		}
	}

	t.Logf("✅ KCP 不通时降级为双 TCP leg 成功 (建连耗时 %v, leg=%v, 含 KCP 握手超时)", dur, legIDs)
}

func TestDualDial_KCPLateWithinHandshake_CoexistsWithTCP(t *testing.T) {
	t.Setenv("BNFS_DISABLE_KCP", "")
	t.Setenv("BNFS_TEST_ACK_DELAY", "350ms")

	relayAddr := startStabilityRelay(t)
	serverID, err := newRelayTestIdentity("dual-late-kcp-server")
	if err != nil {
		t.Fatalf("创建 server 身份失败: %v", err)
	}
	serverStream, err := TryRegisterRelayStream(serverID.publicKey, relayAddr)
	if err != nil {
		t.Fatalf("server dual 注册失败: %v", err)
	}
	defer serverStream.Close()

	connID := "dual-late-kcp-test"
	header := &network.Header{NodeId: serverID.nodeID, NodeIdVersion: 1, ConnectionId: connID}
	body := &network.Message{Header: header, Payload: []byte("late-kcp-client")}

	startedAt := time.Now()
	stream, err := clientStream(body, relayAddr, serverID.nodeID, connID, true)
	if err != nil {
		t.Fatalf("慢 KCP dual 拨号失败: %v", err)
	}
	defer stream.Close()
	elapsed := time.Since(startedAt)

	dual, ok := stream.(*DualStream)
	if !ok {
		t.Fatalf("期望返回 *DualStream, 实际 %T", stream)
	}
	dual.mu.RLock()
	kcpLegs := 0
	tcpLegs := 0
	legIDs := make([]streamTransport, 0, len(dual.legs))
	for id, entry := range dual.legs {
		legIDs = append(legIDs, id)
		switch entry.family {
		case streamTransportKCP:
			kcpLegs++
		case streamTransportTCP:
			tcpLegs++
		}
	}
	dual.mu.RUnlock()

	if elapsed <= kcpPriorityWindow {
		t.Fatalf("测试未进入晚到 KCP 分支: elapsed=%v window=%v", elapsed, kcpPriorityWindow)
	}
	if kcpLegs != 1 || tcpLegs != 1 {
		t.Fatalf("200ms 后、握手期限内成功的 KCP 必须与 TCP 共存: kcp=%d tcp=%d legs=%v elapsed=%v",
			kcpLegs, tcpLegs, legIDs, elapsed)
	}
	t.Logf("✅ 晚到 KCP 未被取消并与 TCP 共存: legs=%v elapsed=%v", legIDs, elapsed)
}
