package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
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

	dual.reconnectMu.Lock()
	_, hasKCPDialer := dual.reconnectDialers[streamTransportKCP]
	_, hasTCPDialer := dual.reconnectDialers[streamTransportTCP]
	_, hasBackupTCPDialer := dual.reconnectDialers[relayBackupLegID(streamTransportTCP)]
	dual.reconnectMu.Unlock()
	if hasKCPDialer {
		t.Fatal("初始 KCP 从未建立时不应保留 KCP 重连拨号器")
	}
	if !hasTCPDialer || !hasBackupTCPDialer {
		t.Fatalf("双 TCP 的两个重连拨号器必须保留: tcp=%v tcp#2=%v", hasTCPDialer, hasBackupTCPDialer)
	}

	dual.EnableReconnectSurvival()
	time.Sleep(2 * initialReconnectBackoff)
	dual.reconnectMu.Lock()
	kcpReconnectActive := dual.reconnectActive[streamTransportKCP]
	dual.reconnectMu.Unlock()
	if kcpReconnectActive {
		t.Fatal("启用连接存活后不应后台复活从未建立过的 KCP leg")
	}

	t.Logf("✅ KCP 不通时降级为双 TCP leg 成功 (建连耗时 %v, leg=%v, 含 KCP 握手超时)", dur, legIDs)
}

func TestDualDial_SingleTCPModeSkipsBackupLeg(t *testing.T) {
	t.Setenv("BNFS_SINGLE_TCP", "1")
	t.Setenv("BNFS_DISABLE_KCP", "")
	relayAddr, cover, stop := startTCPOnlyRelayWithCover(t)
	defer stop()

	serverID, err := newRelayTestIdentity("single-tcp-server")
	if err != nil {
		t.Fatalf("创建 server 身份失败: %v", err)
	}
	serverStream, err := TryRegisterRelayStream(serverID.publicKey, relayAddr)
	if err != nil {
		t.Fatalf("server 单 TCP 注册失败: %v", err)
	}
	defer serverStream.Close()
	if err := waitForRelayGroup(cover, serverID.nodeID, 3*time.Second); err != nil {
		t.Fatalf("等待 server StreamGroup 就绪超时: %v", err)
	}

	connID := "single-tcp-capacity-test"
	body := &network.Message{
		Header:  &network.Header{NodeId: serverID.nodeID, NodeIdVersion: 1, ConnectionId: connID},
		Payload: []byte("single-tcp-client"),
	}
	stream, err := clientStream(body, relayAddr, serverID.nodeID, connID, true)
	if err != nil {
		t.Fatalf("单 TCP 拨号失败: %v", err)
	}
	defer stream.Close()

	dual, ok := stream.(*DualStream)
	if !ok {
		t.Fatalf("期望返回 *DualStream, 实际 %T", stream)
	}
	dual.mu.RLock()
	legCount := len(dual.legs)
	for id, entry := range dual.legs {
		if id != streamTransportTCP || entry.family != streamTransportTCP {
			dual.mu.RUnlock()
			t.Fatalf("单 TCP 模式出现非主 TCP leg: id=%s family=%s", id, entry.family)
		}
	}
	dual.mu.RUnlock()
	if legCount != 1 {
		t.Fatalf("单 TCP 模式必须只有 1 条 leg, 实际 %d", legCount)
	}

	dual.reconnectMu.Lock()
	_, hasPrimary := dual.reconnectDialers[streamTransportTCP]
	_, hasKCP := dual.reconnectDialers[streamTransportKCP]
	_, hasBackup := dual.reconnectDialers[relayBackupLegID(streamTransportTCP)]
	dual.reconnectMu.Unlock()
	if !hasPrimary || hasKCP || hasBackup {
		t.Fatalf("单 TCP 重连拨号器错误: primary=%v kcp=%v backup=%v", hasPrimary, hasKCP, hasBackup)
	}

	cover.lock.RLock()
	serverGroup := cover.StreamGroup[serverID.nodeID]
	cover.lock.RUnlock()
	if serverGroup == nil {
		t.Fatal("server StreamGroup 丢失")
	}
	serverGroup.lock.Lock()
	serverDual, serverOK := serverGroup.relayStream.(*DualStream)
	serverGroup.lock.Unlock()
	if !serverOK {
		t.Fatalf("server 注册流应为 *DualStream, 实际 %T", serverGroup.relayStream)
	}
	serverDual.mu.RLock()
	serverLegCount := len(serverDual.legs)
	serverDual.mu.RUnlock()
	if serverLegCount != 1 {
		t.Fatalf("单 TCP 模式 server 侧必须只有 1 条 leg, 实际 %d", serverLegCount)
	}
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

func TestRelayRegistrationRefreshReplacesProtocolLegs(t *testing.T) {
	t.Setenv("BNFS_DISABLE_KCP", "")
	addr := freeLocalAddr(t)
	starter := NewRelayStarter(addr)
	go starter.StartListen()
	t.Cleanup(func() { starter.Close() })

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	identity, err := newRelayTestIdentity("registration-refresh-server")
	if err != nil {
		t.Fatalf("创建 server 身份失败: %v", err)
	}
	first, err := TryRegisterRelayStream(identity.publicKey, addr)
	if err != nil {
		t.Fatalf("首次 dual 注册失败: %v", err)
	}
	defer first.Close()
	if err := waitForRelayGroup(starter.Cover(), identity.nodeID, 3*time.Second); err != nil {
		t.Fatalf("等待首次注册 StreamGroup 失败: %v", err)
	}

	second, err := TryRegisterRelayStream(identity.publicKey, addr)
	if err != nil {
		t.Fatalf("相同身份刷新 dual 注册失败: %v", err)
	}
	defer second.Close()

	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		starter.Cover().lock.RLock()
		group := starter.Cover().StreamGroup[identity.nodeID]
		starter.Cover().lock.RUnlock()
		if group == nil {
			time.Sleep(20 * time.Millisecond)
			continue
		}
		group.lock.Lock()
		dual, ok := group.relayStream.(*DualStream)
		group.lock.Unlock()
		if !ok {
			t.Fatalf("relay 注册流应为 DualStream，实际 %T", group.relayStream)
		}
		dual.mu.RLock()
		legCount := len(dual.legs)
		kcpLegs := 0
		tcpLegs := 0
		for _, entry := range dual.legs {
			switch entry.family {
			case streamTransportKCP:
				kcpLegs++
			case streamTransportTCP:
				tcpLegs++
			}
		}
		dual.mu.RUnlock()
		if legCount == 2 && kcpLegs == 1 && tcpLegs == 1 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("相同身份刷新注册后应替换旧协议 leg，而不是持续累积")
}

func TestRelayRegistrationRefreshRoutesFirstFrameToNewTCPGeneration(t *testing.T) {
	t.Setenv("BNFS_DISABLE_KCP", "1")
	relayAddr, cover, stop := startTCPOnlyRelayWithCover(t)
	defer stop()

	serverIdentity, err := newRelayTestIdentity("registration-refresh-tcp-server")
	if err != nil {
		t.Fatalf("创建 server 身份失败: %v", err)
	}
	firstGeneration, err := TryRegisterRelayStream(serverIdentity.publicKey, relayAddr)
	if err != nil {
		t.Fatalf("首次双 TCP 注册失败: %v", err)
	}
	defer firstGeneration.Close()
	if err := waitForRelayGroup(cover, serverIdentity.nodeID, 3*time.Second); err != nil {
		t.Fatalf("等待首次注册 StreamGroup 失败: %v", err)
	}

	secondGeneration, err := TryRegisterRelayStream(serverIdentity.publicKey, relayAddr)
	if err != nil {
		t.Fatalf("第二代双 TCP 注册失败: %v", err)
	}
	defer secondGeneration.Close()

	clientIdentity, err := newRelayTestIdentity("registration-refresh-tcp-client")
	if err != nil {
		t.Fatalf("创建 client 身份失败: %v", err)
	}
	client, connectionID, err := TryConnectTCPStream(relayAddr, serverIdentity.nodeID, clientIdentity.publicKey)
	if err != nil {
		t.Fatalf("业务 client 连接失败: %v", err)
	}
	defer client.Close()

	noiseHello := []byte("BNFSN2H1-regression-noise")
	if err := client.SendMessage(context.Background(), &network.Message{
		Header: &network.Header{
			NodeId:        serverIdentity.nodeID,
			NodeIdVersion: 1,
			ConnectionId:  connectionID,
		},
		Payload: noiseHello,
	}); err != nil {
		t.Fatalf("发送后续 Noise hello 失败: %v", err)
	}

	firstMessage, err := nextNonKeepAliveMessage(context.Background(), secondGeneration, 3*time.Second)
	if err != nil {
		t.Fatalf("第二代注册流未收到业务首帧: %v", err)
	}
	if got, want := string(firstMessage.Payload), clientIdentity.publicKey; got != want {
		t.Fatalf("第二代注册流首帧错位: got=%q want client public key %q", got, want)
	}
}

func TestRelayRegistrationRefreshReplacesTwoTCPGenerationSlots(t *testing.T) {
	t.Setenv("BNFS_DISABLE_KCP", "1")
	relayAddr, cover, stop := startTCPOnlyRelayWithCover(t)
	defer stop()

	serverIdentity, err := newRelayTestIdentity("registration-refresh-two-tcp-slots")
	if err != nil {
		t.Fatalf("创建 server 身份失败: %v", err)
	}
	firstGeneration, err := TryRegisterRelayStream(serverIdentity.publicKey, relayAddr)
	if err != nil {
		t.Fatalf("首次双 TCP 注册失败: %v", err)
	}
	defer firstGeneration.Close()
	firstSlots := waitForRelayTCPStableSlots(t, cover, serverIdentity.nodeID, nil)
	oldStreams := make(map[network.Stream]struct{}, len(firstSlots))
	for _, stream := range firstSlots {
		oldStreams[stream] = struct{}{}
	}

	secondGeneration, err := TryRegisterRelayStream(serverIdentity.publicKey, relayAddr)
	if err != nil {
		t.Fatalf("第二代双 TCP 注册失败: %v", err)
	}
	defer secondGeneration.Close()
	secondSlots := waitForRelayTCPStableSlots(t, cover, serverIdentity.nodeID, oldStreams)

	if secondSlots[streamTransportTCP] == firstSlots[streamTransportTCP] {
		t.Fatal("第二代 normal TCP 未替换第一代主 slot")
	}
	backupID := relayBackupLegID(streamTransportTCP)
	if secondSlots[backupID] == firstSlots[backupID] {
		t.Fatal("第二代 extra TCP 未替换第一代备用 slot")
	}
}

func TestRelayTCPOnlyRegistrationSurvivesExistingKCPGeneration(t *testing.T) {
	t.Setenv("BNFS_DISABLE_KCP", "")
	relayAddr := freeLocalAddr(t)
	starter := NewRelayStarter(relayAddr)
	go starter.StartListen()
	t.Cleanup(func() { starter.Close() })

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", relayAddr, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	identity, err := newRelayTestIdentity("tcp-only-refresh-existing-kcp")
	if err != nil {
		t.Fatalf("创建注册身份失败: %v", err)
	}
	firstGeneration, err := TryRegisterRelayStream(identity.publicKey, relayAddr)
	if err != nil {
		t.Fatalf("首代 KCP/TCP 注册失败: %v", err)
	}
	defer firstGeneration.Close()
	if err := waitForRelayGroup(starter.Cover(), identity.nodeID, 3*time.Second); err != nil {
		t.Fatalf("等待首代注册失败: %v", err)
	}

	t.Setenv("BNFS_DISABLE_KCP", "1")
	secondGeneration, err := TryRegisterRelayStream(identity.publicKey, relayAddr)
	if err != nil {
		t.Fatalf("旧 KCP 存在时双 TCP 注册失败: %v", err)
	}
	defer secondGeneration.Close()

	dual, ok := secondGeneration.(*DualStream)
	if !ok {
		t.Fatalf("双 TCP 注册应返回 DualStream，实际 %T", secondGeneration)
	}
	dual.mu.RLock()
	legCount := len(dual.legs)
	tcpLegs := 0
	for _, entry := range dual.legs {
		if entry != nil && entry.family == streamTransportTCP {
			tcpLegs++
		}
	}
	dual.mu.RUnlock()
	if legCount != 2 || tcpLegs != 2 {
		t.Fatalf("双 TCP 注册不完整: legs=%d tcp=%d", legCount, tcpLegs)
	}
}

func TestRelayExtraSlotReplacementIsBounded(t *testing.T) {
	dual := newDualStream("stable-slot-node", "")
	defer dual.Close()
	primary := newRelaySlotTestTCPStream(t, "primary")
	if err := dual.AttachStreamCoexist(primary, false); err != nil {
		t.Fatalf("挂载主 slot 失败: %v", err)
	}

	var previousExtra *TcpStream
	backupID := relayBackupLegID(streamTransportTCP)
	for index := 0; index < 20; index++ {
		extra := newRelaySlotTestTCPStream(t, "extra")
		if err := dual.AttachStreamCoexist(extra, true); err != nil {
			t.Fatalf("第 %d 次挂载备用 slot 失败: %v", index+1, err)
		}
		if previousExtra != nil && !previousExtra.IsClosed() {
			t.Fatalf("第 %d 次刷新后旧 extra leg 仍未关闭", index+1)
		}

		dual.mu.RLock()
		legCount := len(dual.legs)
		primaryEntry := dual.legs[streamTransportTCP]
		backupEntry := dual.legs[backupID]
		preferred := dual.preferred
		dual.mu.RUnlock()
		if legCount != 2 {
			t.Fatalf("同族 Relay leg 必须限制为主备两条，实际=%d", legCount)
		}
		if primaryEntry == nil || primaryEntry.stream != primary {
			t.Fatal("刷新 extra leg 不应替换 normal 主 slot")
		}
		if backupEntry == nil || backupEntry.stream != extra {
			t.Fatal("最新 extra leg 未占据稳定备用 slot")
		}
		if preferred != streamTransportTCP {
			t.Fatalf("刷新 extra leg 不应改变 preferred，实际=%s", preferred)
		}
		previousExtra = extra
	}
}

func TestRelayNormalSlotPromotesAfterPrimaryDetach(t *testing.T) {
	dual := newDualStream("preferred-slot-node", "")
	defer dual.Close()
	oldPrimary := newRelaySlotTestTCPStream(t, "old-primary")
	backup := newRelaySlotTestTCPStream(t, "backup")
	if err := dual.AttachStreamCoexist(oldPrimary, false); err != nil {
		t.Fatalf("挂载旧主 slot 失败: %v", err)
	}
	if err := dual.AttachStreamCoexist(backup, true); err != nil {
		t.Fatalf("挂载备用 slot 失败: %v", err)
	}

	dual.handleLegFailure(streamTransportTCP, oldPrimary)
	if got, want := dual.preferredTransport(), relayBackupLegID(streamTransportTCP); got != want {
		t.Fatalf("主 slot 掉线后备用 slot 应接管: got=%s want=%s", got, want)
	}

	newPrimary := newRelaySlotTestTCPStream(t, "new-primary")
	if err := dual.AttachStreamCoexist(newPrimary, false); err != nil {
		t.Fatalf("刷新 normal 主 slot 失败: %v", err)
	}
	primaryID, primary, _, _ := dual.sendOrder()
	if primaryID != streamTransportTCP || primary != newPrimary {
		t.Fatalf("新 normal 必须原子恢复为 preferred: id=%s stream=%T", primaryID, primary)
	}
	dual.mu.RLock()
	backupEntry := dual.legs[relayBackupLegID(streamTransportTCP)]
	legCount := len(dual.legs)
	dual.mu.RUnlock()
	if legCount != 2 || backupEntry == nil || backupEntry.stream != backup {
		t.Fatal("恢复 normal 主 slot 时不应替换健康备用 slot")
	}
}

func TestRelayExtraLegArrivingFirstKeepsStableBackupSlot(t *testing.T) {
	extra := newRelaySlotTestTCPStream(t, "extra-first")
	dual := relaySlotDualStream(extra, true)
	defer dual.Close()
	backupID := relayBackupLegID(streamTransportTCP)
	if got := dual.preferredTransport(); got != backupID {
		t.Fatalf("extra 先到时应暂由备用 slot 承载: got=%s want=%s", got, backupID)
	}

	normal := newRelaySlotTestTCPStream(t, "normal-later")
	if err := dual.AttachStreamCoexist(normal, false); err != nil {
		t.Fatalf("后到 normal 挂载主 slot 失败: %v", err)
	}
	dual.mu.RLock()
	primaryEntry := dual.legs[streamTransportTCP]
	backupEntry := dual.legs[backupID]
	legCount := len(dual.legs)
	preferred := dual.preferred
	dual.mu.RUnlock()
	if legCount != 2 || primaryEntry == nil || primaryEntry.stream != normal ||
		backupEntry == nil || backupEntry.stream != extra {
		t.Fatal("extra/normal 乱序到达后未落入稳定主备 slot")
	}
	if preferred != streamTransportTCP {
		t.Fatalf("normal 到达后必须恢复主 slot preferred，实际=%s", preferred)
	}
}

func TestRelayExtraTCPRegistrationRetiresStaleKCPGeneration(t *testing.T) {
	dual := newDualStreamWithPump("stale-kcp-registration", "", false)
	staleKCP := newRelaySlotTestTCPStream(t, "stale-kcp")
	if err := dual.attachWithID(streamTransportKCP, streamTransportKCP, staleKCP); err != nil {
		t.Fatalf("挂载旧 KCP slot 失败: %v", err)
	}
	group := &StreamGroup{
		relayStream:   dual,
		relayFrame:    dual.EnableFrameRelay(),
		connectionMap: make(map[string]*connectionResource),
		frameRoutes:   newFrameRouteRegistry(),
		ctx:           dual.ctx,
		cancelFunc:    func() {},
		nodeId:        dual.NodeId(),
	}
	t.Cleanup(group.Close)

	normal := newRelaySlotTestTCPStream(t, "new-normal")
	if err := group.AttachRelayStreamCoexist(normal, false); err != nil {
		t.Fatalf("挂载新代 normal TCP 失败: %v", err)
	}
	extra := newRelaySlotTestTCPStream(t, "new-extra")
	if err := group.AttachRelayStreamCoexist(extra, true); err != nil {
		t.Fatalf("挂载新代 extra TCP 失败: %v", err)
	}

	dual.mu.RLock()
	_, kcpPresent := dual.legs[streamTransportKCP]
	primary := dual.legs[streamTransportTCP]
	backup := dual.legs[relayBackupLegID(streamTransportTCP)]
	preferred := dual.preferred
	legCount := len(dual.legs)
	dual.mu.RUnlock()
	if kcpPresent || legCount != 2 {
		t.Fatalf("双 TCP 代次确认后必须清除旧 KCP: kcp=%v legs=%d", kcpPresent, legCount)
	}
	if primary == nil || primary.stream != normal || backup == nil || backup.stream != extra {
		t.Fatal("清除旧 KCP 后双 TCP 稳定主备 slot 不完整")
	}
	if preferred != streamTransportTCP {
		t.Fatalf("旧 KCP 淘汰后 normal TCP 应成为 preferred，实际=%s", preferred)
	}
	if !staleKCP.IsClosed() {
		t.Fatal("旧 KCP carrier 未关闭")
	}
	endpoint, ok := group.relayFrame.(*DualFrameRelayEndpoint)
	if !ok {
		t.Fatalf("relay frame endpoint 类型错误: %T", group.relayFrame)
	}
	endpoint.mu.Lock()
	_, staleAdapter := endpoint.adapters[streamTransportKCP]
	endpoint.mu.Unlock()
	if staleAdapter {
		t.Fatal("旧 KCP frame adapter 未从 relay endpoint 摘除")
	}
}

func TestRelayExtraFirstWaitsForNormalBeforeRetiringStaleKCP(t *testing.T) {
	dual := newDualStreamWithPump("stale-kcp-extra-first", "", false)
	staleKCP := newRelaySlotTestTCPStream(t, "stale-kcp-extra-first")
	if err := dual.attachWithID(streamTransportKCP, streamTransportKCP, staleKCP); err != nil {
		t.Fatalf("挂载旧 KCP slot 失败: %v", err)
	}
	group := &StreamGroup{
		relayStream:   dual,
		relayFrame:    dual.EnableFrameRelay(),
		connectionMap: make(map[string]*connectionResource),
		frameRoutes:   newFrameRouteRegistry(),
		ctx:           dual.ctx,
		cancelFunc:    func() {},
		nodeId:        dual.NodeId(),
	}
	t.Cleanup(group.Close)

	extra := newRelaySlotTestTCPStream(t, "new-extra-first")
	if err := group.AttachRelayStreamCoexist(extra, true); err != nil {
		t.Fatalf("先挂载新代 extra TCP 失败: %v", err)
	}
	dual.mu.RLock()
	kcpBeforeNormal := dual.legs[streamTransportKCP]
	preferredBeforeNormal := dual.preferred
	dual.mu.RUnlock()
	if kcpBeforeNormal == nil || kcpBeforeNormal.stream != staleKCP || staleKCP.IsClosed() {
		t.Fatal("仅 extra TCP 到达时不得淘汰仍可能有效的 KCP")
	}
	if preferredBeforeNormal != streamTransportKCP {
		t.Fatalf("双 TCP 未齐备前 KCP 应保持 preferred，实际=%s", preferredBeforeNormal)
	}

	normal := newRelaySlotTestTCPStream(t, "new-normal-later")
	if err := group.AttachRelayStreamCoexist(normal, false); err != nil {
		t.Fatalf("后挂载新代 normal TCP 失败: %v", err)
	}
	dual.mu.RLock()
	_, kcpAfterNormal := dual.legs[streamTransportKCP]
	primary := dual.legs[streamTransportTCP]
	backup := dual.legs[relayBackupLegID(streamTransportTCP)]
	preferred := dual.preferred
	legCount := len(dual.legs)
	dual.mu.RUnlock()
	if kcpAfterNormal || legCount != 2 {
		t.Fatalf("extra/normal 齐备后必须清除旧 KCP: kcp=%v legs=%d", kcpAfterNormal, legCount)
	}
	if primary == nil || primary.stream != normal || backup == nil || backup.stream != extra {
		t.Fatal("extra-first 淘汰旧 KCP 后双 TCP 主备 slot 不完整")
	}
	if preferred != streamTransportTCP {
		t.Fatalf("淘汰旧 KCP 后必须明确选择 normal TCP，实际=%s", preferred)
	}
	if !staleKCP.IsClosed() {
		t.Fatal("双 TCP 齐备后旧 KCP carrier 未关闭")
	}
}

type retirementLockProbeStream struct {
	*TcpStream
	dual               *DualStream
	group              *StreamGroup
	closeCalled        atomic.Bool
	attachLockReleased atomic.Bool
	groupLockReleased  atomic.Bool
}

func (s *retirementLockProbeStream) TCPStream() *TcpStream {
	return s.TcpStream
}

func (s *retirementLockProbeStream) Close() error {
	s.closeCalled.Store(true)
	if s.dual.attachMu.TryLock() {
		s.attachLockReleased.Store(true)
		s.dual.attachMu.Unlock()
	}
	if s.group.lock.TryLock() {
		s.groupLockReleased.Store(true)
		s.group.lock.Unlock()
	}
	return s.TcpStream.Close()
}

func TestRelayStaleKCPClosesOutsideTopologyLocks(t *testing.T) {
	dual := newDualStreamWithPump("stale-kcp-lock-boundary", "", false)
	carrier := newRelaySlotTestTCPStream(t, "stale-kcp-lock-boundary")
	probe := &retirementLockProbeStream{TcpStream: carrier, dual: dual}
	if err := dual.attachWithID(streamTransportKCP, streamTransportKCP, probe); err != nil {
		t.Fatalf("挂载受控旧 KCP slot 失败: %v", err)
	}
	group := &StreamGroup{
		relayStream:   dual,
		relayFrame:    dual.EnableFrameRelay(),
		connectionMap: make(map[string]*connectionResource),
		frameRoutes:   newFrameRouteRegistry(),
		ctx:           dual.ctx,
		cancelFunc:    func() {},
		nodeId:        dual.NodeId(),
	}
	probe.group = group
	t.Cleanup(group.Close)

	normal := newRelaySlotTestTCPStream(t, "lock-boundary-normal")
	if err := group.AttachRelayStreamCoexist(normal, false); err != nil {
		t.Fatalf("挂载 normal TCP 失败: %v", err)
	}
	extra := newRelaySlotTestTCPStream(t, "lock-boundary-extra")
	if err := group.AttachRelayStreamCoexist(extra, true); err != nil {
		t.Fatalf("挂载 extra TCP 失败: %v", err)
	}

	if !probe.closeCalled.Load() {
		t.Fatal("双 TCP 齐备后未关闭旧 KCP")
	}
	if !probe.attachLockReleased.Load() {
		t.Fatal("旧 KCP Close 在 attachMu 持锁期间执行")
	}
	if !probe.groupLockReleased.Load() {
		t.Fatal("旧 KCP Close 在 StreamGroup.lock 持锁期间执行")
	}
}

type blockingIdentityTCPStream struct {
	*TcpStream
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (s *blockingIdentityTCPStream) SetIdentity(nodeID, connectionID string) {
	s.once.Do(func() { close(s.entered) })
	<-s.release
	s.TcpStream.SetIdentity(nodeID, connectionID)
}

func (s *blockingIdentityTCPStream) TCPStream() *TcpStream {
	return s.TcpStream
}

func TestRelayConcurrentSameSlotRefreshKeepsFrameAdapterAligned(t *testing.T) {
	dual := newDualStreamWithPump("concurrent-slot-node", "", false)
	defer dual.Close()
	oldPrimary := newRelaySlotTestTCPStream(t, "old-primary")
	if err := dual.AttachStreamCoexist(oldPrimary, false); err != nil {
		t.Fatalf("挂载旧主 slot 失败: %v", err)
	}
	endpoint := dual.EnableFrameRelay()
	if endpoint == nil {
		t.Fatal("启用 frame relay 失败")
	}

	firstCarrier := newRelaySlotTestTCPStream(t, "first-refresh")
	first := &blockingIdentityTCPStream{
		TcpStream: firstCarrier,
		entered:   make(chan struct{}),
		release:   make(chan struct{}),
	}
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- dual.AttachStreamCoexist(first, false)
	}()
	select {
	case <-first.entered:
	case <-time.After(time.Second):
		t.Fatal("第一条刷新未进入受控 identity 阶段")
	}

	second := newRelaySlotTestTCPStream(t, "second-refresh")
	secondDone := make(chan error, 1)
	go func() {
		secondDone <- dual.AttachStreamCoexist(second, false)
	}()

	secondFinishedBeforeRelease := false
	select {
	case err := <-secondDone:
		if err != nil {
			t.Fatalf("第二条并发刷新失败: %v", err)
		}
		secondFinishedBeforeRelease = true
	case <-time.After(100 * time.Millisecond):
	}
	close(first.release)
	if err := <-firstDone; err != nil {
		t.Fatalf("第一条并发刷新失败: %v", err)
	}
	if !secondFinishedBeforeRelease {
		if err := <-secondDone; err != nil {
			t.Fatalf("第二条并发刷新失败: %v", err)
		}
	}

	dual.mu.RLock()
	leg := dual.legs[streamTransportTCP]
	dual.mu.RUnlock()
	endpoint.mu.Lock()
	adapter := endpoint.adapters[streamTransportTCP]
	endpoint.mu.Unlock()
	if leg == nil || adapter == nil {
		t.Fatalf("并发刷新后 slot 不完整: leg=%v adapter=%v", leg, adapter)
	}
	if got := tcpStreamFromStream(leg.stream); got != adapter.stream {
		t.Fatalf("DualStream 与 frame endpoint slot 反向覆盖: dual=%p adapter=%p", got, adapter.stream)
	}
	if adapter.stream.IsClosed() {
		t.Fatal("并发刷新后现役 frame adapter 已关闭")
	}
}

func TestRelayDelayedStaleDetachKeepsReplacementAdapter(t *testing.T) {
	dual := newDualStreamWithPump("stale-detach-node", "", false)
	defer dual.Close()
	oldPrimary := newRelaySlotTestTCPStream(t, "old-detached-primary")
	if err := dual.AttachStreamCoexist(oldPrimary, false); err != nil {
		t.Fatalf("挂载旧主 slot 失败: %v", err)
	}
	endpoint := dual.EnableFrameRelay()
	if endpoint == nil {
		t.Fatal("启用 frame relay 失败")
	}
	replacement := newRelaySlotTestTCPStream(t, "replacement-primary")
	if err := dual.AttachStreamCoexist(replacement, false); err != nil {
		t.Fatalf("替换主 slot 失败: %v", err)
	}

	endpoint.onLegDetached(streamTransportTCP, oldPrimary)

	dual.mu.RLock()
	leg := dual.legs[streamTransportTCP]
	dual.mu.RUnlock()
	endpoint.mu.Lock()
	adapter := endpoint.adapters[streamTransportTCP]
	endpoint.mu.Unlock()
	if leg == nil || leg.stream != replacement {
		t.Fatal("延迟 detach 改坏了 DualStream replacement slot")
	}
	if adapter == nil || adapter.stream != replacement {
		t.Fatal("延迟 detach 摘除了更新代次的 frame adapter")
	}
}

func TestRelayDetachDuringAttachDoesNotPublishOrphanAdapter(t *testing.T) {
	dual := newDualStreamWithPump("detach-during-attach", "", false)
	defer dual.Close()
	oldPrimary := newRelaySlotTestTCPStream(t, "old-before-detach")
	if err := dual.AttachStreamCoexist(oldPrimary, false); err != nil {
		t.Fatalf("挂载旧主 slot 失败: %v", err)
	}
	endpoint := dual.EnableFrameRelay()
	if endpoint == nil {
		t.Fatal("启用 frame relay 失败")
	}
	dual.EnableReconnectSurvival()
	dual.SetReconnectDialer(streamTransportTCP, func(context.Context) (network.Stream, error) {
		return nil, ErrRelayCandidatesExhausted
	})

	carrier := newRelaySlotTestTCPStream(t, "detached-before-endpoint")
	replacement := &blockingIdentityTCPStream{
		TcpStream: carrier,
		entered:   make(chan struct{}),
		release:   make(chan struct{}),
	}
	attachDone := make(chan error, 1)
	go func() {
		attachDone <- dual.AttachStreamCoexist(replacement, false)
	}()
	select {
	case <-replacement.entered:
	case <-time.After(time.Second):
		t.Fatal("replacement 未进入受控 identity 阶段")
	}

	dual.detach(streamTransportTCP, replacement)
	close(replacement.release)
	if err := <-attachDone; err == nil {
		t.Fatal("已被 detach 的 replacement 仍成功发布到 frame endpoint")
	}

	dual.mu.RLock()
	leg := dual.legs[streamTransportTCP]
	dual.mu.RUnlock()
	endpoint.mu.Lock()
	adapter := endpoint.adapters[streamTransportTCP]
	endpoint.mu.Unlock()
	if leg != nil || adapter != nil {
		t.Fatalf("detach/attach 交错后拓扑未清空: leg=%v adapter=%v", leg, adapter)
	}
}

func TestEnableFrameRelaySnapshotCannotOverwriteNewSlot(t *testing.T) {
	dual := newDualStreamWithPump("enable-snapshot-node", "", false)
	defer dual.Close()
	oldPrimary := newRelaySlotTestTCPStream(t, "snapshot-old")
	if err := dual.AttachStreamCoexist(oldPrimary, false); err != nil {
		t.Fatalf("挂载旧主 slot 失败: %v", err)
	}

	oldPrimary.frameTapMu.Lock()
	tapLocked := true
	defer func() {
		if tapLocked {
			oldPrimary.frameTapMu.Unlock()
		}
	}()
	enableDone := make(chan *DualFrameRelayEndpoint, 1)
	go func() {
		enableDone <- dual.EnableFrameRelay()
	}()
	deadline := time.Now().Add(time.Second)
	for {
		dual.mu.RLock()
		published := dual.frameEndpoint != nil
		dual.mu.RUnlock()
		if published {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("EnableFrameRelay 未发布 endpoint")
		}
		time.Sleep(time.Millisecond)
	}

	replacement := newRelaySlotTestTCPStream(t, "snapshot-new")
	attachDone := make(chan error, 1)
	go func() {
		attachDone <- dual.AttachStreamCoexist(replacement, false)
	}()
	attachFinishedBeforeRelease := false
	select {
	case err := <-attachDone:
		if err != nil {
			t.Fatalf("并发 replacement attach 失败: %v", err)
		}
		attachFinishedBeforeRelease = true
	case <-time.After(100 * time.Millisecond):
	}

	oldPrimary.frameTapMu.Unlock()
	tapLocked = false
	endpoint := <-enableDone
	if endpoint == nil {
		t.Fatal("EnableFrameRelay 返回 nil")
	}
	if !attachFinishedBeforeRelease {
		if err := <-attachDone; err != nil {
			t.Fatalf("并发 replacement attach 失败: %v", err)
		}
	}

	dual.mu.RLock()
	leg := dual.legs[streamTransportTCP]
	dual.mu.RUnlock()
	endpoint.mu.Lock()
	adapter := endpoint.adapters[streamTransportTCP]
	endpoint.mu.Unlock()
	if leg == nil || leg.stream != replacement {
		t.Fatal("EnableFrameRelay snapshot 改坏了 DualStream replacement slot")
	}
	if adapter == nil || adapter.stream != replacement {
		t.Fatal("EnableFrameRelay snapshot-old 反向覆盖了 replacement adapter")
	}
}

func TestRelayRegistrationResumeCannotReplaceOccupiedNormalOrExtraSlot(t *testing.T) {
	oldNormal := newRelaySlotTestTCPStream(t, "registration-old-normal")
	group := newStreamGroupWithRelaySlot(oldNormal, defaultHookfunc, false)
	t.Cleanup(group.Close)
	oldExtra := newRelaySlotTestTCPStream(t, "registration-old-extra")
	if err := group.AttachRelayStreamCoexist(oldExtra, true); err != nil {
		t.Fatalf("挂载旧代 extra slot 失败: %v", err)
	}

	resumedNormal := newRelaySlotTestTCPStream(t, "registration-resume-normal")
	if err := group.attachRelayStreamCoexist(resumedNormal, false, true); !errors.Is(err, ErrResumeSlotOccupied) {
		t.Fatalf("resume normal 应被明确拒绝: err=%v", err)
	}
	resumedExtra := newRelaySlotTestTCPStream(t, "registration-resume-extra")
	if err := group.attachRelayStreamCoexist(resumedExtra, true, true); !errors.Is(err, ErrResumeSlotOccupied) {
		t.Fatalf("resume extra 应被明确拒绝: err=%v", err)
	}

	group.lock.Lock()
	dual := group.relayStream.(*DualStream)
	group.lock.Unlock()
	backupID := relayBackupLegID(streamTransportTCP)
	dual.mu.RLock()
	normalAfterResume := dual.legs[streamTransportTCP]
	extraAfterResume := dual.legs[backupID]
	dual.mu.RUnlock()
	if normalAfterResume == nil || normalAfterResume.stream != oldNormal ||
		extraAfterResume == nil || extraAfterResume.stream != oldExtra {
		t.Fatal("被拒绝的旧代 resume 改写了注册主备 slot")
	}
	if oldNormal.IsClosed() || oldExtra.IsClosed() {
		t.Fatal("被拒绝的旧代 resume 关闭了健康注册 slot")
	}

	newNormal := newRelaySlotTestTCPStream(t, "registration-new-normal")
	if err := group.attachRelayStreamCoexist(newNormal, false, false); err != nil {
		t.Fatalf("新代 non-resume normal 应允许替换: %v", err)
	}
	newExtra := newRelaySlotTestTCPStream(t, "registration-new-extra")
	if err := group.attachRelayStreamCoexist(newExtra, true, false); err != nil {
		t.Fatalf("新代 non-resume extra 应允许替换: %v", err)
	}
	dual.mu.RLock()
	normalAfterRefresh := dual.legs[streamTransportTCP]
	extraAfterRefresh := dual.legs[backupID]
	dual.mu.RUnlock()
	if normalAfterRefresh == nil || normalAfterRefresh.stream != newNormal ||
		extraAfterRefresh == nil || extraAfterRefresh.stream != newExtra {
		t.Fatal("新代 non-resume 未替换注册主备 slot")
	}
	if !oldNormal.IsClosed() || !oldExtra.IsClosed() {
		t.Fatal("新代 non-resume 替换后旧注册 slot 未关闭")
	}
}

func TestBusinessStreamOnResumeCannotReplaceOccupiedNormalOrExtraSlot(t *testing.T) {
	relay := newRelaySlotTestTCPStream(t, "business-target")
	group := newStreamGroupWithRelaySlot(relay, defaultHookfunc, false)
	t.Cleanup(group.Close)
	connectionID := "business-resume-slots"
	message := func(flags uint8) *network.Message {
		return &network.Message{Header: &network.Header{
			NodeId:       group.nodeId,
			ConnectionId: connectionID,
			LegFlags:     flags,
		}}
	}

	oldNormal := newRelaySlotTestTCPStream(t, "business-old-normal")
	forward, err := group.StreamOn(oldNormal, message(0))
	if err != nil || !forward {
		t.Fatalf("首次 business normal 接入失败: forward=%v err=%v", forward, err)
	}
	oldExtra := newRelaySlotTestTCPStream(t, "business-old-extra")
	forward, err = group.StreamOn(oldExtra, message(network.LegFlagExtra))
	if err != nil || forward {
		t.Fatalf("首次 business extra 接入失败: forward=%v err=%v", forward, err)
	}

	resumedNormal := newRelaySlotTestTCPStream(t, "business-resume-normal")
	if _, err := group.StreamOn(resumedNormal, message(network.LegFlagResume)); !errors.Is(err, ErrResumeSlotOccupied) {
		t.Fatalf("business resume normal 应被明确拒绝: err=%v", err)
	}
	resumedExtra := newRelaySlotTestTCPStream(t, "business-resume-extra")
	resumeExtraFlags := uint8(network.LegFlagResume | network.LegFlagExtra)
	if _, err := group.StreamOn(resumedExtra, message(resumeExtraFlags)); !errors.Is(err, ErrResumeSlotOccupied) {
		t.Fatalf("business resume extra 应被明确拒绝: err=%v", err)
	}

	group.lock.Lock()
	resource := group.connectionMap[connectionID]
	group.lock.Unlock()
	if resource == nil {
		t.Fatal("被拒绝的 business resume 删除了现役连接")
	}
	dual, ok := resource.stream.(*DualStream)
	if !ok {
		t.Fatalf("business 逻辑流类型错误: %T", resource.stream)
	}
	dual.mu.RLock()
	normalAfterResume := dual.legs[streamTransportTCP]
	extraAfterResume := dual.legs[relayBackupLegID(streamTransportTCP)]
	dual.mu.RUnlock()
	if normalAfterResume == nil || normalAfterResume.stream != oldNormal ||
		extraAfterResume == nil || extraAfterResume.stream != oldExtra {
		t.Fatal("被拒绝的 business resume 改写了现役主备 slot")
	}
	if oldNormal.IsClosed() || oldExtra.IsClosed() {
		t.Fatal("被拒绝的 business resume 关闭了现役主备 slot")
	}
}

func TestResumeCanFillMissingOrClosedRelaySlot(t *testing.T) {
	dual := newDualStreamWithPump("resume-fill-slot", "", false)
	t.Cleanup(func() { _ = dual.Close() })
	closedNormal := newRelaySlotTestTCPStream(t, "closed-normal")
	if err := dual.AttachStreamCoexist(closedNormal, false); err != nil {
		t.Fatalf("挂载待关闭 normal slot 失败: %v", err)
	}
	if err := closedNormal.Close(); err != nil {
		t.Fatalf("关闭旧 normal slot 失败: %v", err)
	}

	resumedNormal := newRelaySlotTestTCPStream(t, "resumed-normal")
	if err := dual.attachStreamCoexist(resumedNormal, false, true); err != nil {
		t.Fatalf("resume 应允许填补已关闭 normal slot: %v", err)
	}
	resumedExtra := newRelaySlotTestTCPStream(t, "resumed-extra")
	if err := dual.attachStreamCoexist(resumedExtra, true, true); err != nil {
		t.Fatalf("resume 应允许填补缺失 extra slot: %v", err)
	}

	dual.mu.RLock()
	normal := dual.legs[streamTransportTCP]
	extra := dual.legs[relayBackupLegID(streamTransportTCP)]
	dual.mu.RUnlock()
	if normal == nil || normal.stream != resumedNormal || extra == nil || extra.stream != resumedExtra {
		t.Fatal("resume 未正确填补已关闭/缺失 slot")
	}
}

func waitForRelayTCPStableSlots(t *testing.T, cover *TransportCover, nodeID string, excluded map[network.Stream]struct{}) map[streamTransport]network.Stream {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		cover.lock.RLock()
		group := cover.StreamGroup[nodeID]
		cover.lock.RUnlock()
		if group == nil {
			time.Sleep(10 * time.Millisecond)
			continue
		}
		group.lock.Lock()
		dual, ok := group.relayStream.(*DualStream)
		group.lock.Unlock()
		if !ok {
			t.Fatalf("relay 注册流应为 DualStream，实际 %T", group.relayStream)
		}

		dual.mu.RLock()
		valid := len(dual.legs) == 2 && dual.preferred == streamTransportTCP
		slots := make(map[streamTransport]network.Stream, 2)
		if valid {
			for id, entry := range dual.legs {
				if entry == nil || entry.family != streamTransportTCP ||
					(id != streamTransportTCP && id != relayBackupLegID(streamTransportTCP)) {
					valid = false
					break
				}
				if _, stale := excluded[entry.stream]; stale {
					valid = false
					break
				}
				slots[id] = entry.stream
			}
		}
		dual.mu.RUnlock()
		if valid && len(slots) == 2 {
			return slots
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("等待 Relay 双 TCP 稳定主备 slot 超时")
	return nil
}

func newRelaySlotTestTCPStream(t *testing.T, nodeID string) *TcpStream {
	t.Helper()
	local, remote := net.Pipe()
	stream := NewTCPStream(nodeID, "", local)
	t.Cleanup(func() {
		_ = stream.Close()
		_ = remote.Close()
	})
	return stream
}
