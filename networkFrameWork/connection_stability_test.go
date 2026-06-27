package networkFrameWork

import (
	"bnfs_p2p/crypoto"
	"bnfs_p2p/network"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xtaci/kcp-go/v5"
)

// controllableConn 包装一条底层 net.Conn，用来在测试里手动模拟 KCP 链路的两种异常：
//   - block():      之后所有 Read/Write 立即返回错误，模拟链路被阻塞（读写不再推进）。
//   - disconnect(): 直接关闭底层连接，模拟链路硬断开。
//
// 两种情况都会让 TcpStream.readLoop 读到错误并 failAndClose，
// 进而触发 DualStream 把这条 KCP leg 摘除、把流量切到 TCP。
type controllableConn struct {
	net.Conn
	mu      sync.Mutex
	blocked bool
}

func (c *controllableConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	blocked := c.blocked
	c.mu.Unlock()
	if blocked {
		return 0, errors.New("controllableConn: kcp link blocked")
	}
	return c.Conn.Write(p)
}

func (c *controllableConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	blocked := c.blocked
	c.mu.Unlock()
	if blocked {
		return 0, errors.New("controllableConn: kcp link blocked")
	}
	return c.Conn.Read(p)
}

func (c *controllableConn) block() {
	c.mu.Lock()
	c.blocked = true
	c.mu.Unlock()
}

func (c *controllableConn) disconnect() {
	_ = c.Conn.Close()
}

const (
	stabilityHelloRoute    = "/clientHello"
	stabilityHelloAckRoute = "/clientHello-ack"
)

// freeLocalAddr 预留一个本地 TCP 端口随即释放，返回 host:port 供 RelayStarter 复用。
// RelayStarter 会在同一端口上同时监听 TCP 与 KCP(UDP)，UDP 与已释放的 TCP 端口互不冲突。
func freeLocalAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve local addr: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

// startStabilityRelay 拉起一个 relayNode（RelayStarter，等价于 pacakgeTest 里的 "server" 模式），
// 等到 TCP 监听就绪后返回，并注册关闭钩子。
func startStabilityRelay(t *testing.T) string {
	t.Helper()
	addr := freeLocalAddr(t)
	starter := NewRelayStarter(addr)
	go starter.StartListen()
	t.Cleanup(func() { starter.Close() })

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return addr
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("relay %s not ready in time", addr)
	return ""
}

// dialControllableDual 复刻 clientStream(isDefault=true) 的 dual 拨号路径，
// 唯一区别是把 KCP leg 的底层连接包进 controllableConn，方便测试手动阻塞 / 断连。
// 返回的 *DualStream 默认 preferred=KCP（首个 attach 的 leg），SendMessage 会优先走 KCP。
func dialControllableDual(t *testing.T, relayAddr, targetNodeId, clientPubHex, connectionId string) (*DualStream, *controllableConn, error) {
	t.Helper()
	header := &network.Header{
		NodeId:        targetNodeId,
		NodeIdVersion: 1,
		ConnectionId:  connectionId,
	}
	body := &network.Message{Header: header, Payload: []byte(clientPubHex)}

	// --- KCP leg（可控）---
	kcpConn, err := kcp.DialWithOptions(relayAddr, nil, 1, 1)
	if err != nil {
		return nil, nil, fmt.Errorf("kcp dial: %w", err)
	}
	kcpConn.SetNoDelay(1, 50, 2, 1)
	kcpConn.SetMtu(1000)
	kcpConn.SetWriteBuffer(4 * 1024 * 1024)
	kcpConn.SetWindowSize(128, 512)
	ctrl := &controllableConn{Conn: kcpConn}
	kcpStreamObj := startTcpStream(targetNodeId, connectionId, ctrl)
	hctx, cancel := context.WithTimeout(context.Background(), dialHandshakeTimeout)
	if err := kcpStreamObj.SendMessage(hctx, cloneMessage(body)); err != nil {
		cancel()
		kcpStreamObj.Close()
		return nil, nil, fmt.Errorf("kcp first message: %w", err)
	}
	cancel()
	go kcpStreamObj.keepLive()

	// --- TCP leg ---
	tcpStreamObj, err := tcpClientStream(cloneMessage(body), relayAddr, targetNodeId, connectionId)
	if err != nil {
		kcpStreamObj.Close()
		return nil, nil, fmt.Errorf("tcp leg: %w", err)
	}

	dual := newDualStream(targetNodeId, connectionId)
	if err := dual.attach(streamTransportKCP, kcpStreamObj); err != nil {
		kcpStreamObj.Close()
		tcpStreamObj.Close()
		return nil, nil, fmt.Errorf("attach kcp: %w", err)
	}
	if err := dual.attach(streamTransportTCP, tcpStreamObj); err != nil {
		tcpStreamObj.Close()
		dual.Close()
		return nil, nil, fmt.Errorf("attach tcp: %w", err)
	}

	// 注入与生产一致的重连 dialer：KCP 断连后会用一条全新的(健康的)真实 KCP leg 恢复链路，
	// TCP 同理。这样测试覆盖的是真实的 failover + 自愈行为。
	template := cloneMessage(body)
	dual.SetReconnectDialer(streamTransportKCP, func(ctx context.Context) (network.Stream, error) {
		return kcpStreamContext(ctx, cloneMessage(template), relayAddr, targetNodeId, connectionId)
	})
	dual.SetReconnectDialer(streamTransportTCP, func(ctx context.Context) (network.Stream, error) {
		return tcpClientStreamContext(ctx, cloneMessage(template), relayAddr, targetNodeId, connectionId)
	})
	return dual, ctrl, nil
}

// runStabilityServerNode 模拟 serverNode（pacakgeTest 的 relayServer 模式）：
//  1. 以注册流身份连上 relayNode；
//  2. 等 client 的首条 hello，推导 clientNodeId 并绑定身份；
//  3. 完成 TLS 握手（serverNode 侧），装上加密套件；
//  4. 进入回显循环：收到 /clientHello 就原样回 /clientHello-ack。
//
// ready 在注册流建立后关闭，通知主测试可以启动 client 拨号。
func runStabilityServerNode(
	ctx context.Context,
	relayAddr string,
	identity *relayTestIdentity,
	recorder *stabilityServerRecorder,
	ready chan<- struct{},
	errCh chan<- error,
) {
	stream, err := TryRegisterRelayStream(identity.publicKey, relayAddr)
	if err != nil {
		errCh <- fmt.Errorf("server register: %w", err)
		return
	}
	defer stream.Close()
	close(ready)

	// 等 client 首条 hello（payload = client 公钥 hex），据此推导对端身份并绑定。
	firstCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	hello, err := nextNonKeepAliveMessage(firstCtx, stream, 15*time.Second)
	cancel()
	if err != nil {
		if ctx.Err() == nil {
			errCh <- fmt.Errorf("server wait first hello: %w", err)
		}
		return
	}
	clientNodeId := hashHex(string(hello.Payload))
	if !SetStreamIdentity(stream, clientNodeId, hello.Header.ConnectionId) {
		errCh <- errors.New("server SetStreamIdentity failed")
		return
	}

	crypto, err := crypoto.NewTLSCrypto(stream, identity.keyPair)
	if err != nil {
		if ctx.Err() == nil {
			errCh <- fmt.Errorf("server NewTLSCrypto: %w", err)
		}
		return
	}
	stream.SetCryptoSuite(crypto)

	for {
		msg, err := nextNonKeepAliveMessage(ctx, stream, 20*time.Second)
		if err != nil {
			if ctx.Err() == nil {
				errCh <- fmt.Errorf("server read loop: %w", err)
			}
			return
		}
		if msg.Header.RouteName != stabilityHelloRoute {
			continue
		}
		// 记录真正抵达 Server 端的 clientHello，供测试断言。
		recorder.record(msg.Payload)
		ack := &network.Message{
			Header: &network.Header{
				RouteName:     stabilityHelloAckRoute,
				NodeId:        identity.nodeID,
				NodeIdVersion: 1,
				ConnectionId:  msg.Header.ConnectionId,
			},
			Payload: append([]byte(nil), msg.Payload...),
		}
		if err := sendMessageWithTimeout(ctx, stream, ack, 10*time.Second); err != nil {
			if ctx.Err() == nil {
				errCh <- fmt.Errorf("server send ack: %w", err)
			}
			return
		}
	}
}

// connectStabilityClient 模拟 clientStream 一侧：通过 relayNode 连到 serverNode，
// 并完成 TLS 握手装上加密套件。带重试，吸收 "serverNode 注册流尚未在 relay 建组" 的就绪窗口。
func connectStabilityClient(
	t *testing.T,
	ctx context.Context,
	relayAddr, serverNodeId string,
	identity *relayTestIdentity,
) (*DualStream, *controllableConn, string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		connectionId := uuid.New().String()
		dual, ctrl, err := dialControllableDual(t, relayAddr, serverNodeId, identity.publicKey, connectionId)
		if err != nil {
			lastErr = err
			time.Sleep(200 * time.Millisecond)
			continue
		}
		crypto, err := crypoto.NewTLSCrypto(dual, identity.keyPair)
		if err != nil {
			lastErr = fmt.Errorf("client NewTLSCrypto: %w", err)
			dual.Close()
			time.Sleep(200 * time.Millisecond)
			continue
		}
		dual.SetCryptoSuite(crypto)
		return dual, ctrl, connectionId
	}
	t.Fatalf("client failed to establish secure connection: %v", lastErr)
	return nil, nil, ""
}

// sendHelloExpectAck 发送一条 /clientHello 业务消息并等待 serverNode 回显，校验 payload 一致。
//
// 注意：本系统是「至少一次」投递。client 的逻辑流由 KCP+TCP 两条 leg 组成，
// 每条 leg 各自维护独立的 E2E 去重表；在 KCP 受损 / failover 期间，
// 同一条 ack 可能分别经两条 leg 各投递一次，导致 NextMessage 读到重复(且陈旧)的 ack。
// 因此这里不假设「下一条 ack 就是本次的回显」，而是持续读取并丢弃 payload 不匹配的陈旧 ack，
// 直到读到与本次发送 payload 一致的回显为止；若始终读不到则由 ctx 超时判失败。
func sendHelloExpectAck(t *testing.T, ctx context.Context, stream network.Stream, serverNodeId, connectionId string, payload []byte) {
	t.Helper()
	hello := &network.Message{
		Header: &network.Header{
			RouteName:     stabilityHelloRoute,
			NodeId:        serverNodeId,
			NodeIdVersion: 1,
			ConnectionId:  connectionId,
		},
		Payload: append([]byte(nil), payload...),
	}
	if err := sendMessageWithTimeout(ctx, stream, hello, 10*time.Second); err != nil {
		t.Fatalf("send clientHello: %v", err)
	}
	for {
		ack, err := nextNonKeepAliveMessage(ctx, stream, 15*time.Second)
		if err != nil {
			t.Fatalf("wait clientHello ack (payload=%q): %v", payload, err)
		}
		if ack.Header.RouteName != stabilityHelloAckRoute {
			continue
		}
		if bytes.Equal(ack.Payload, payload) {
			return
		}
		// 陈旧 / 重复 ack：丢弃并继续等本次回显。
		t.Logf("丢弃陈旧 ack: got=%q want=%q", ack.Payload, payload)
	}
}

// stabilityServerRecorder 记录 serverNode 真正收到的 /clientHello payload（按内容计数）。
// 测试用它在 server 一侧直接断言"第二次 clientHello 确实抵达了真正的 Server 端"，
// 而不是仅凭 client 收到 ack 间接推断。
type stabilityServerRecorder struct {
	mu       sync.Mutex
	received map[string]int
}

func newStabilityServerRecorder() *stabilityServerRecorder {
	return &stabilityServerRecorder{received: make(map[string]int)}
}

func (r *stabilityServerRecorder) record(payload []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.received[string(payload)]++
}

func (r *stabilityServerRecorder) count(payload string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.received[payload]
}

// currentKCPStream 读取 DualStream 当前现役的 KCP leg（白盒：同包测试直接持锁访问）。
// 用来在 disrupt 前后对比 leg 是否被换成了一条全新的流，从而证明发生了真实重连。
func currentKCPStream(d *DualStream) network.Stream {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.streamLocked(streamTransportKCP)
}

// waitForKCPReconnect 轮询等待 DualStream 的 KCP leg 重新建立：
// 现役 KCP leg 非空且不再是 original（说明旧 leg 被摘除、新 leg 已 attach）。
func waitForKCPReconnect(d *DualStream, original network.Stream, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		cur := currentKCPStream(d)
		if cur != nil && cur != original {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// runConnectionStabilityCase 搭建 clientStream -> relayNode <- serverNode 的三方拓扑，
// 建立端到端安全连接后，先确认链路可用，再通过 disrupt 回调手动破坏 client 的 KCP leg
// （阻塞或断连），随后立刻再发一个 /clientHello。断言：KCP 受损后逻辑连接依旧稳定，
// 消息能经由 TCP failover / KCP 自愈成功往返。
func runConnectionStabilityCase(t *testing.T, disrupt func(t *testing.T, ctrl *controllableConn)) {
	relayAddr := startStabilityRelay(t)

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()

	serverIdentity, err := newRelayTestIdentity("stability-server")
	if err != nil {
		t.Fatalf("server identity: %v", err)
	}
	clientIdentity, err := newRelayTestIdentity("stability-client")
	if err != nil {
		t.Fatalf("client identity: %v", err)
	}

	recorder := newStabilityServerRecorder()
	ready := make(chan struct{})
	errCh := make(chan error, 1)
	go runStabilityServerNode(ctx, relayAddr, serverIdentity, recorder, ready, errCh)

	select {
	case <-ready:
	case err := <-errCh:
		t.Fatalf("server node failed before ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("server node not ready in time")
	}
	// 给 relay 一点时间把注册流建成 StreamGroup，client 才能寻址过来。
	time.Sleep(300 * time.Millisecond)

	clientStreamObj, ctrl, connectionId := connectStabilityClient(t, ctx, relayAddr, serverIdentity.nodeID, clientIdentity)
	defer clientStreamObj.Close()

	// 1) 安全连接建立后先验证链路本身可用（此时 KCP 仍为 preferred leg）。
	const beforePayload = "hello-before-disrupt"
	sendHelloExpectAck(t, ctx, clientStreamObj, serverIdentity.nodeID, connectionId, []byte(beforePayload))
	if recorder.count(beforePayload) < 1 {
		t.Fatalf("server 未收到首条 clientHello %q", beforePayload)
	}
	// 记录破坏前的现役 KCP leg，稍后用它确认 leg 被换成了新的一条。
	originalKCP := currentKCPStream(clientStreamObj)
	if originalKCP == nil {
		t.Fatal("破坏前 KCP leg 不应为空")
	}
	select {
	case err := <-errCh:
		t.Fatalf("server error after first hello: %v", err)
	default:
	}

	// 2) 手动破坏 KCP leg（阻塞 / 断连），随后立刻再发一个 clientHello。
	const afterPayload = "hello-after-kcp-disrupt"
	disrupt(t, ctrl)
	sendHelloExpectAck(t, ctx, clientStreamObj, serverIdentity.nodeID, connectionId, []byte(afterPayload))

	// 断言一：真正的 Server 端确实收到了第二次 clientHello。
	if recorder.count(afterPayload) < 1 {
		t.Fatalf("KCP 受损后 server 未收到第二次 clientHello %q", afterPayload)
	}

	// 断言二：client -> relayServer 之间的 KCP 连接已重新建立（新 leg 替换了被破坏的旧 leg）。
	if !waitForKCPReconnect(clientStreamObj, originalKCP, 15*time.Second) {
		t.Fatal("KCP leg 在受损后未重新连接")
	}
	t.Log("KCP leg 已重新连接")

	// 断言三：断开重连完成后，再做完整往返，验证「断开重连后双向仍能收到正确消息」。
	//   - sendHelloExpectAck 内部校验 client 收到的 ack payload 与发送内容逐字节一致（client 端正确性）；
	//   - recorder.count 再校验 server 端确实收到了同样的内容（server 端正确性）。
	// 不手动 pin 具体 leg：failover 后 DualStream 由健康 leg 承载流量，KCP 自愈后纳入备份，
	// 这里要验证的是「逻辑连接在断开重连后整体可靠」，而非某条物理 leg。
	const reconnectPayload = "hello-over-reconnected-link"
	sendHelloExpectAck(t, ctx, clientStreamObj, serverIdentity.nodeID, connectionId, []byte(reconnectPayload))
	if recorder.count(reconnectPayload) < 1 {
		t.Fatalf("断开重连后 server 未收到消息 %q", reconnectPayload)
	}
	t.Log("断开重连后双向消息内容校验通过")

	// 4) 破坏后链路应保持稳定：连续再跑几轮往返，确认不是偶发成功。
	for i := 0; i < 3; i++ {
		payload := fmt.Sprintf("hello-post-disrupt-%d", i)
		sendHelloExpectAck(t, ctx, clientStreamObj, serverIdentity.nodeID, connectionId, []byte(payload))
		if recorder.count(payload) < 1 {
			t.Fatalf("server 未收到稳定性校验消息 %q", payload)
		}
	}

	select {
	case err := <-errCh:
		t.Fatalf("server error during stability check: %v", err)
	default:
	}
}

// TestConnectionStabilityKCPBlocked 模拟 KCP 链路被阻塞（读写卡死/不再推进）后，
// client 立刻再发 clientHello，验证 DualStream 能在帧级别切换到可靠 TCP leg 完成往返。
func TestConnectionStabilityKCPBlocked(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping connection stability test in short mode")
	}
	runConnectionStabilityCase(t, func(t *testing.T, ctrl *controllableConn) {
		t.Log("手动阻塞 client 的 KCP leg")
		ctrl.block()
	})
}

// TestConnectionStabilityKCPDisconnected 模拟 KCP 链路被硬断开后，
// client 立刻再发 clientHello，验证逻辑连接仍稳定（TCP failover + KCP 自愈重连）。
func TestConnectionStabilityKCPDisconnected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping connection stability test in short mode")
	}
	runConnectionStabilityCase(t, func(t *testing.T, ctrl *controllableConn) {
		t.Log("手动断开 client 的 KCP leg")
		ctrl.disconnect()
	})
}
