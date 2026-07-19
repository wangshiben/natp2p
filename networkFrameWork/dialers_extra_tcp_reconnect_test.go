package networkFrameWork

import (
	"bnfs_p2p/network"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func startTCPRelayDroppingAccept(t *testing.T, dropOrdinal int32) (
	string,
	*TransportCover,
	<-chan struct{},
	*atomic.Int32,
	func(),
) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("启动 TCP-only Relay 失败: %v", err)
	}
	cover := NewTransportCover()
	dropped := make(chan struct{})
	var dropOnce sync.Once
	var accepted atomic.Int32
	go func() {
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			if accepted.Add(1) == dropOrdinal {
				dropOnce.Do(func() { close(dropped) })
				_ = connection.Close()
				continue
			}
			go func() { _ = cover.ListenTCPConnection(connection) }()
		}
	}()
	return listener.Addr().String(), cover, dropped, &accepted, func() { _ = listener.Close() }
}

func TestDualDialExtraTCPInitialFailureReconnectsOnlyBackupTCP(t *testing.T) {
	t.Setenv("BNFS_DISABLE_KCP", "")
	relayAddr, cover, droppedExtra, accepted, stop := startTCPRelayDroppingAccept(t, 3)
	defer stop()

	serverIdentity, err := newRelayTestIdentity("extra-tcp-reconnect-server")
	if err != nil {
		t.Fatalf("创建 Server 身份失败: %v", err)
	}
	serverStream, err := registerRelayTCPOnly(serverIdentity, relayAddr)
	if err != nil {
		t.Fatalf("注册 Server 失败: %v", err)
	}
	defer serverStream.Close()
	if err := waitForRelayGroup(cover, serverIdentity.nodeID, 3*time.Second); err != nil {
		t.Fatalf("等待 Server 注册完成失败: %v", err)
	}

	clientIdentity, err := newRelayTestIdentity("extra-tcp-reconnect-client")
	if err != nil {
		t.Fatalf("创建 Client 身份失败: %v", err)
	}
	connectionID := "extra-tcp-initial-failure"
	firstMessage := &network.Message{
		Header: &network.Header{
			NodeId:        serverIdentity.nodeID,
			NodeIdVersion: 1,
			ConnectionId:  connectionID,
		},
		Payload: []byte(clientIdentity.publicKey),
	}
	stream, err := clientStream(firstMessage, relayAddr, serverIdentity.nodeID, connectionID, true)
	if err != nil {
		t.Fatalf("主 TCP 成功时 dual 拨号不应因 extra TCP 首拨失败而失败: %v", err)
	}
	defer stream.Close()
	select {
	case <-droppedExtra:
	default:
		t.Fatal("未按预期关闭 extra TCP 的首次接入")
	}

	dual, ok := stream.(*DualStream)
	if !ok {
		t.Fatalf("期望 *DualStream，实际 %T", stream)
	}
	backupID := relayBackupLegID(streamTransportTCP)
	dual.mu.RLock()
	initialPrimary := dual.legs[streamTransportTCP]
	initialBackup := dual.legs[backupID]
	initialKCP := dual.legs[streamTransportKCP]
	dual.mu.RUnlock()
	if initialPrimary == nil || initialPrimary.family != streamTransportTCP {
		t.Fatal("主 TCP 未在 extra 首拨失败后保持存活")
	}
	if initialBackup != nil {
		t.Fatal("被关闭的 extra TCP 首拨不应留下 tcp#2 leg")
	}
	if initialKCP != nil {
		t.Fatal("初始 KCP 失败后不应存在 KCP leg")
	}

	dual.reconnectMu.Lock()
	_, hasKCPDialer := dual.reconnectDialers[streamTransportKCP]
	_, hasBackupDialer := dual.reconnectDialers[backupID]
	dual.reconnectMu.Unlock()
	if hasKCPDialer {
		t.Fatal("初始 KCP 从未建立时不得保留 KCP 重连拨号器")
	}
	if !hasBackupDialer {
		t.Fatal("extra TCP 首拨失败后必须保留 tcp#2 重连拨号器")
	}

	dual.EnableReconnectSurvival()
	deadline := time.Now().Add(4 * time.Second)
	for !dual.HasStream(backupID) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !dual.HasStream(backupID) {
		t.Fatal("启用 reconnect survival 后未恢复 tcp#2 冗余")
	}

	dual.mu.RLock()
	primary := dual.legs[streamTransportTCP]
	backup := dual.legs[backupID]
	_, hasKCP := dual.legs[streamTransportKCP]
	legCount := len(dual.legs)
	dual.mu.RUnlock()
	if primary == nil || primary.family != streamTransportTCP ||
		backup == nil || backup.family != streamTransportTCP {
		t.Fatal("恢复后双 TCP 主备槽位不完整")
	}
	if hasKCP || legCount != 2 {
		t.Fatalf("恢复冗余时不得复活 KCP: hasKCP=%v legs=%d", hasKCP, legCount)
	}

	dual.reconnectMu.Lock()
	kcpReconnectActive := dual.reconnectActive[streamTransportKCP]
	_, hasKCPDialer = dual.reconnectDialers[streamTransportKCP]
	dual.reconnectMu.Unlock()
	if kcpReconnectActive || hasKCPDialer {
		t.Fatalf("reconnect survival 错误调度 KCP: active=%v dialer=%v", kcpReconnectActive, hasKCPDialer)
	}
	if accepted.Load() < 4 {
		t.Fatalf("tcp#2 恢复未产生新的 TCP 接入: accepted=%d", accepted.Load())
	}
}
