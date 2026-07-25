package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"
)

type ipv6RelayDialPolicy struct {
	mu       sync.Mutex
	target   RelayDialTarget
	failures []error
	signal   chan struct{}
}

func (p *ipv6RelayDialPolicy) CurrentRelay() (RelayDialTarget, error) {
	return p.target, nil
}

func (p *ipv6RelayDialPolicy) ReportRelayDialResult(_ RelayDialTarget, err error) {
	if err == nil {
		return
	}
	p.mu.Lock()
	p.failures = append(p.failures, err)
	p.mu.Unlock()
}

func (p *ipv6RelayDialPolicy) RelayChangeSignal() <-chan struct{} {
	return p.signal
}

func (p *ipv6RelayDialPolicy) dialFailures() []error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]error(nil), p.failures...)
}

func reserveIPv6Addr(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("运行环境未启用 IPv6 loopback: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("释放 IPv6 测试端口失败: %v", err)
	}
	return addr
}

func startIPv6Relay(t *testing.T) (string, *TransportCover) {
	t.Helper()
	addr := reserveIPv6Addr(t)
	starter := NewRelayStarter(addr)
	go starter.StartListen()
	t.Cleanup(starter.Close)

	select {
	case <-starter.Ready():
		return addr, starter.Cover()
	case <-starter.Done():
		t.Fatalf("IPv6 Relay 启动失败: %v", starter.StartError())
	case <-time.After(3 * time.Second):
		t.Fatalf("等待 IPv6 Relay %s 就绪超时", addr)
	}
	return "", nil
}

func assertDualIPv6Transports(t *testing.T, stream network.Stream) {
	t.Helper()
	dual, ok := stream.(*DualStream)
	if !ok {
		t.Fatalf("期望 IPv6 dual stream，实际 %T", stream)
	}
	dual.mu.RLock()
	defer dual.mu.RUnlock()

	var tcpLegs, kcpLegs int
	for _, entry := range dual.legs {
		switch entry.family {
		case streamTransportTCP:
			tcpLegs++
		case streamTransportKCP:
			kcpLegs++
		}
	}
	if tcpLegs != 1 || kcpLegs != 1 {
		t.Fatalf("IPv6 dual stream 链路不完整: TCP=%d KCP=%d", tcpLegs, kcpLegs)
	}
}

func TestIPv6RelaySupportsControlTCPAndDualTransports(t *testing.T) {
	t.Setenv("BNFS_DISABLE_KCP", "")
	relayAddr, cover := startIPv6Relay(t)

	serverIdentity, err := newRelayTestIdentity("ipv6-relay-server")
	if err != nil {
		t.Fatalf("创建 IPv6 Server 身份失败: %v", err)
	}
	serverStream, err := TryRegisterRelayStream(serverIdentity.publicKey, relayAddr)
	if err != nil {
		t.Fatalf("通过 IPv6 注册 Relay 失败: %v", err)
	}
	defer serverStream.Close()
	assertDualIPv6Transports(t, serverStream)
	if err := waitForRelayGroup(cover, serverIdentity.nodeID, 3*time.Second); err != nil {
		t.Fatal(err)
	}

	clientIdentity, err := newRelayTestIdentity("ipv6-relay-client")
	if err != nil {
		t.Fatalf("创建 IPv6 Client 身份失败: %v", err)
	}
	controlStream, _, err := TryConnectControlStreamTCP(
		relayAddr, serverIdentity.nodeID, clientIdentity.publicKey, "/ipv6-control")
	if err != nil {
		t.Fatalf("IPv6 TCP 控制流失败: %v", err)
	}
	_ = controlStream.Close()

	policy := &ipv6RelayDialPolicy{
		target: RelayDialTarget{Address: relayAddr, Generation: 1},
		signal: make(chan struct{}),
	}
	clientStream, _, err := TryConnectTCPStreamWithRelayPolicy(
		policy, serverIdentity.nodeID, clientIdentity.publicKey)
	if err != nil {
		t.Fatalf("IPv6 dual 业务流失败: %v", err)
	}
	defer clientStream.Close()
	assertDualIPv6Transports(t, clientStream)
	EnableReconnectSurvival(clientStream)

	time.Sleep(2 * time.Second)
	assertDualIPv6Transports(t, clientStream)
	if failures := policy.dialFailures(); len(failures) != 0 {
		t.Fatalf("健康 IPv6 Relay 被错误上报为失败: %v", failures)
	}
}

func TestDialBridgeMuxSessionSupportsIPv6TCP(t *testing.T) {
	t.Setenv("BNFS_BRIDGE_KCP", "0")
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("运行环境未启用 IPv6 loopback: %v", err)
	}
	defer listener.Close()

	result := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			result <- acceptErr
			return
		}
		defer connection.Close()
		if tcpAddr, ok := connection.RemoteAddr().(*net.TCPAddr); !ok || tcpAddr.IP.To4() != nil {
			result <- fmt.Errorf("桥接连接未使用 IPv6: %v", connection.RemoteAddr())
			return
		}
		if err := connection.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
			result <- err
			return
		}
		frame, readErr := network.ReadFrame(connection)
		if readErr != nil {
			result <- readErr
			return
		}
		message, assembleErr := network.AssembleFrames([]*network.Frame{frame})
		if assembleErr != nil {
			result <- assembleErr
			return
		}
		if message.Header.RouteName != muxHandshakeRoute {
			result <- fmt.Errorf("桥接握手路由=%q，期望 %q", message.Header.RouteName, muxHandshakeRoute)
			return
		}
		result <- nil
	}()

	session, err := DialBridgeMuxSession(context.Background(), listener.Addr().String(), "ipv6-relay")
	if err != nil {
		t.Fatalf("IPv6 Relay 桥接拨号失败: %v", err)
	}
	defer session.Close()

	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("IPv6 Relay 桥接握手失败: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("等待 IPv6 Relay 桥接握手超时")
	}
}
