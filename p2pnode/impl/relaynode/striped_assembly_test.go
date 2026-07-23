package relaynode

import (
	"bnfs_p2p/networkFrameWork"
	"context"
	"net"
	"testing"
	"time"
)

type stripedMuxTestLeg struct {
	client       *networkFrameWork.MuxSession
	server       *networkFrameWork.MuxSession
	clientStream *networkFrameWork.MuxStream
	serverStream *networkFrameWork.MuxStream
}

func openStripedMuxTestLeg(t *testing.T, connID, target, pubKey string, encodedIndex, legCount int, flags uint8) *stripedMuxTestLeg {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	client := networkFrameWork.NewMuxSession(context.Background(), clientConn, true)
	server := networkFrameWork.NewMuxSession(context.Background(), serverConn, false)
	clientStream, err := client.OpenStreamLeg(connID, target, pubKey, encodedIndex, legCount, flags)
	if err != nil {
		_ = client.Close()
		_ = server.Close()
		t.Fatalf("OpenStreamLeg: %v", err)
	}
	serverStream, err := server.Accept()
	if err != nil {
		_ = client.Close()
		_ = server.Close()
		t.Fatalf("Accept: %v", err)
	}
	leg := &stripedMuxTestLeg{
		client:       client,
		server:       server,
		clientStream: clientStream,
		serverStream: serverStream,
	}
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return leg
}

func newStripedCollector(t *testing.T, timeout time.Duration) *RelayNode {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return &RelayNode{
		ctx:                  ctx,
		stripedLegs:          make(map[string]*stripedAccept),
		stripedAcceptTimeout: timeout,
	}
}

func waitForStripedCondition(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !condition() {
		t.Fatal("等待 striped 状态变化超时")
	}
}

func TestOpenLogicalConnAllOrNothing(t *testing.T) {
	firstClientConn, firstServerConn := net.Pipe()
	firstClient := networkFrameWork.NewMuxSession(context.Background(), firstClientConn, true)
	firstServer := networkFrameWork.NewMuxSession(context.Background(), firstServerConn, false)
	defer firstClient.Close()
	defer firstServer.Close()

	secondClientConn, secondServerConn := net.Pipe()
	secondClient := networkFrameWork.NewMuxSession(context.Background(), secondClientConn, true)
	secondServer := networkFrameWork.NewMuxSession(context.Background(), secondServerConn, false)
	defer secondClient.Close()
	defer secondServer.Close()

	const connID = "partial-striped-open"
	occupied, err := secondClient.OpenStream(connID, "target", "pub-key")
	if err != nil {
		t.Fatalf("预占第二条 session: %v", err)
	}
	defer occupied.Close()
	if _, err := secondServer.Accept(); err != nil {
		t.Fatalf("接收预占 stream: %v", err)
	}

	pool := &relayPeerPool{
		conns: []*physConn{
			{sess: firstClient},
			{sess: secondClient},
		},
	}
	logicalConn, err := pool.OpenLogicalConn(connID, "target", "pub-key", 2)
	if err == nil || logicalConn != nil {
		if logicalConn != nil {
			_ = logicalConn.Close()
		}
		t.Fatalf("部分 OPEN 不应成功: conn=%v err=%v", logicalConn, err)
	}

	firstAccepted, err := firstServer.Accept()
	if err != nil {
		t.Fatalf("接收第一条已打开 leg: %v", err)
	}
	waitForStripedCondition(t, func() bool {
		return firstClient.ActiveStreams() == 0 && firstServer.ActiveStreams() == 0
	})
	select {
	case <-firstAccepted.Done():
	default:
		t.Fatal("部分 OPEN 失败后第一条 leg 未关闭")
	}
}

func TestCollectStripedLegRetryDoesNotMixAttempts(t *testing.T) {
	node := newStripedCollector(t, time.Second)
	old := openStripedMuxTestLeg(t, "retry-striped", "target", "pub-key", poolMaxConns, 3, 0)
	newSecond := openStripedMuxTestLeg(t, "retry-striped", "target", "pub-key", 2*poolMaxConns+1, 3, 0)
	lateOld := openStripedMuxTestLeg(t, "retry-striped", "target", "pub-key", poolMaxConns+2, 3, 0)
	newFirst := openStripedMuxTestLeg(t, "retry-striped", "target", "pub-key", 2*poolMaxConns, 3, 0)

	node.collectStripedLeg(old.serverStream)
	node.collectStripedLeg(newSecond.serverStream)
	node.collectStripedLeg(lateOld.serverStream)
	node.collectStripedLeg(newFirst.serverStream)

	node.mu.RLock()
	accept := node.stripedLegs["retry-striped"]
	node.mu.RUnlock()
	if accept == nil || accept.attempt != 2 || len(accept.legs) != 2 {
		t.Fatalf("重试代次归并错误: %#v", accept)
	}
	if accept.legs[0] != newFirst.serverStream || accept.legs[1] != newSecond.serverStream {
		t.Fatal("新代次 leg 未按真实 index 保留")
	}
	select {
	case <-old.serverStream.Done():
	default:
		t.Fatal("新代次到达后旧 incomplete group 未关闭")
	}
	select {
	case <-lateOld.serverStream.Done():
	default:
		t.Fatal("迟到的旧代次 leg 未拒绝")
	}
}

func TestCollectStripedLegRejectsDuplicateIndex(t *testing.T) {
	node := newStripedCollector(t, time.Second)
	first := openStripedMuxTestLeg(t, "duplicate-striped", "target", "pub-key", poolMaxConns, 3, 0)
	duplicate := openStripedMuxTestLeg(t, "duplicate-striped", "target", "pub-key", poolMaxConns, 3, 0)

	node.collectStripedLeg(first.serverStream)
	node.collectStripedLeg(duplicate.serverStream)

	node.mu.RLock()
	accept := node.stripedLegs["duplicate-striped"]
	node.mu.RUnlock()
	if accept == nil || len(accept.legs) != 1 || accept.legs[0] != first.serverStream {
		t.Fatal("重复 index 覆盖了有效 leg")
	}
	select {
	case <-duplicate.serverStream.Done():
	default:
		t.Fatal("重复 index leg 未关闭")
	}
	select {
	case <-first.serverStream.Done():
		t.Fatal("重复 index 不应关闭有效 leg")
	default:
	}
}

func TestCollectStripedLegMetadataConflictFailsClosed(t *testing.T) {
	node := newStripedCollector(t, time.Second)
	first := openStripedMuxTestLeg(t, "conflict-striped", "target-a", "pub-key", poolMaxConns, 3, 0)
	conflict := openStripedMuxTestLeg(t, "conflict-striped", "target-b", "pub-key", poolMaxConns+1, 3, 0)

	node.collectStripedLeg(first.serverStream)
	node.collectStripedLeg(conflict.serverStream)

	node.mu.RLock()
	accept := node.stripedLegs["conflict-striped"]
	node.mu.RUnlock()
	if accept != nil {
		t.Fatal("元数据冲突后 incomplete group 未删除")
	}
	for name, stream := range map[string]*networkFrameWork.MuxStream{
		"已有 leg": first.serverStream,
		"冲突 leg": conflict.serverStream,
	} {
		select {
		case <-stream.Done():
		default:
			t.Fatalf("%s 未关闭", name)
		}
	}
}

func TestCollectStripedLegCloseCleansIncompleteGroup(t *testing.T) {
	node := newStripedCollector(t, time.Second)
	leg := openStripedMuxTestLeg(t, "closed-striped", "target", "pub-key", poolMaxConns, 3, 0)
	node.collectStripedLeg(leg.serverStream)
	if err := leg.clientStream.Close(); err != nil {
		t.Fatalf("关闭对端 leg: %v", err)
	}
	waitForStripedCondition(t, func() bool {
		node.mu.RLock()
		defer node.mu.RUnlock()
		return node.stripedLegs["closed-striped"] == nil
	})
}

func TestCollectStripedLegTimeoutCleansIncompleteGroup(t *testing.T) {
	node := newStripedCollector(t, 25*time.Millisecond)
	leg := openStripedMuxTestLeg(t, "timeout-striped", "target", "pub-key", poolMaxConns, 3, 0)
	node.collectStripedLeg(leg.serverStream)
	waitForStripedCondition(t, func() bool {
		node.mu.RLock()
		defer node.mu.RUnlock()
		return node.stripedLegs["timeout-striped"] == nil
	})
	select {
	case <-leg.serverStream.Done():
	default:
		t.Fatal("超时后 incomplete leg 未关闭")
	}
}
