package relaynode

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestInboundDualSessionLifecycle(t *testing.T) {
	node, err := NewRelayNode(nil, "127.0.0.1:0", "127.0.0.1:9000")
	if err != nil {
		t.Fatal(err)
	}
	defer node.cancel()

	peerID := fmt.Sprintf("%064x", 51)
	oldSessionKey := peerID + "\x00old-session"
	newSessionKey := peerID + "\x00new-session"
	oldFirst, oldFirstDone := trackInboundTestLink(node, peerID, oldSessionKey, 1)
	oldSecond, oldSecondDone := trackInboundTestLink(node, peerID, oldSessionKey, 1)
	if !node.activateInboundLink(oldFirst, peerID) || !node.activateInboundLink(oldSecond, peerID) {
		t.Fatal("同一 dual session 的两条物理 leg 都应被保留")
	}
	assertInboundTestState(t, node, peerID, oldSessionKey, 1, oldFirst, oldSecond)

	newFirst, newFirstDone := trackInboundTestLink(node, peerID, newSessionKey, 2)
	newSecond, newSecondDone := trackInboundTestLink(node, peerID, newSessionKey, 2)
	if !node.activateInboundLink(newFirst, peerID) {
		t.Fatal("更高代 session 应取代旧 session")
	}
	if !node.activateInboundLink(newSecond, peerID) {
		t.Fatal("新 session 的第二条 leg 应与第一条共存")
	}
	assertCanceled(t, oldFirstDone, "旧 session 第一条 leg 未被取消")
	assertCanceled(t, oldSecondDone, "旧 session 第二条 leg 未被取消")
	assertInboundTestState(t, node, peerID, newSessionKey, 2, newFirst, newSecond)

	lateOld, lateOldDone := trackInboundTestLink(node, peerID, oldSessionKey, 1)
	if node.activateInboundLink(lateOld, peerID) {
		t.Fatal("迟到的旧 session leg 不应取代新 session")
	}
	assertCanceled(t, lateOldDone, "迟到的旧 session leg 未被取消")
	assertInboundTestState(t, node, peerID, newSessionKey, 2, newFirst, newSecond)

	done := make(chan struct{})
	go func() {
		node.closePeerLinks()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("closePeerLinks 与 inbound 清理发生锁死")
	}
	assertCanceled(t, newFirstDone, "关闭节点后新 session 第一条 leg 未被取消")
	assertCanceled(t, newSecondDone, "关闭节点后新 session 第二条 leg 未被取消")
	node.mu.RLock()
	activeLinks := node.relayActiveLinks[peerID]
	node.mu.RUnlock()
	if activeLinks != 0 {
		t.Fatalf("关闭当前 inbound 链路后活动计数未归零: got=%d", activeLinks)
	}
}

func trackInboundTestLink(node *RelayNode, peerID, sessionKey string, generation uint64) (*peerLink, <-chan struct{}) {
	linkContext, linkCancel := context.WithCancel(node.ctx)
	link := &peerLink{
		owner: node, inboundSessionKey: sessionKey, inboundGeneration: generation,
		peerID: peerID, countedUp: true,
		ctx: linkContext, cancel: linkCancel,
	}
	node.mu.Lock()
	node.inboundLinks = append(node.inboundLinks, link)
	node.inboundSessionGens[sessionKey] = generation
	node.mu.Unlock()
	node.relayLinkUp(peerID)
	return link, linkContext.Done()
}

func assertInboundTestState(t *testing.T, node *RelayNode, peerID, sessionKey string, generation uint64, want ...*peerLink) {
	t.Helper()
	node.mu.RLock()
	current := node.inboundByPeerID[peerID]
	links := append([]*peerLink(nil), node.inboundLinks...)
	activeLinks := node.relayActiveLinks[peerID]
	node.mu.RUnlock()
	if current.key != sessionKey || current.generation != generation {
		t.Fatalf("当前 inbound session 错误: got=%+v wantKey=%q wantGeneration=%d", current, sessionKey, generation)
	}
	if len(links) != len(want) {
		t.Fatalf("inbound 物理链路数错误: got=%d want=%d", len(links), len(want))
	}
	for _, expected := range want {
		found := false
		for _, actual := range links {
			if actual == expected {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("缺少预期 inbound 物理链路: %p", expected)
		}
	}
	if activeLinks != len(want) {
		t.Fatalf("活动链路计数错误: got=%d want=%d", activeLinks, len(want))
	}
}

func assertCanceled(t *testing.T, done <-chan struct{}, message string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal(message)
	}
}
