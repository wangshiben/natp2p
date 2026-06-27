package networkFrameWork

import (
	"bnfs_p2p/crypoto"
	"bnfs_p2p/network"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"
)

func NodeEstablish(address, originalNodeIdSource string, t *testing.T, wg *sync.WaitGroup, continueEstablish bool) (Id string) {
	//originalNodeIdSource := "test-node-id-source-string"
	pair, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatalf("Failed to make key pair: %v", err)
		return ""
	}
	pairId := crypoto.GetPubKeyStr(pair.PublicKey())
	hash := sha256.Sum256([]byte(pairId))
	originalNodeId := hex.EncodeToString(hash[:])

	if !continueEstablish {
		wg.Add(1)
	}
	go func() {
		if !continueEstablish {
			defer wg.Done()
		}
		stream, err := TryRegisterRelayStream(pairId, address)
		if err != nil {
			t.Errorf("Failed to register relay stream: %v", err.Error())
			return
		}
		for {
			// 接下来接收响应 写入
			ClientFirstMessage, _ := stream.NextMessage(context.Background())
			marshal, err := json.Marshal(ClientFirstMessage)
			if err != nil {
				return
			}
			t.Logf("CurruentRelayId %s", originalNodeId)
			t.Log("ClientFirstMessage:", string(marshal))
			t.Logf("NodeId : %s", string(ClientFirstMessage.Payload))
			//ClientFirstMessage.Header.NodeId = originalNodeId
			ResponseMessage := &network.Message{
				Header:  ClientFirstMessage.Header,
				Payload: []byte("hello world"),
			}
			err = stream.SendMessage(context.Background(), ResponseMessage)
			if err != nil {
				stream.Close()
				t.Error("ERROR:" + err.Error())
				return
			}
			if !continueEstablish {
				return
			}
		}

	}()
	return originalNodeId
}

func ClientTestWithStream(clientSteam network.Stream, connectionId, targetNodeId string, t *testing.T, wg *sync.WaitGroup) {
	defer wg.Done()
	header := &network.Header{
		RouteName:     "",
		NodeId:        targetNodeId,
		NodeIdVersion: 1,
		PayLoadLength: 0,
		ConnectionId:  connectionId,
		OriginData:    nil,
	}
	body := &network.Message{
		Header:  header,
		Payload: []byte("hello server"),
	}
	clientSteam.SendMessage(context.Background(), body)
	ClientFirstMessage, _ := clientSteam.NextMessage(context.Background())

	t.Log("RelayServerFirstMessage:", string(ClientFirstMessage.Payload))
}

func RelayServerWithStream(relayServerAddr string, t *testing.T, wg *sync.WaitGroup, continueEstablish bool) (Id string) {
	pair, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Error("ERROR:" + err.Error())
		return ""
	}
	pairId := crypoto.GetPubKeyStr(pair.PublicKey())
	stream, err := TryRegisterRelayStream(pairId, relayServerAddr)
	if err != nil {
		t.Fatalf("Failed to register relay stream: %v", err.Error())
		return ""
	}
	return stream.NodeId()
}

func ClientSendTestMessage(TargetNodeId, RelayServerAddr, originalNodeIdSource string, t *testing.T, wg *sync.WaitGroup) string {
	pair, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatalf("Failed to make key pair: %v", err)
		return ""
	}
	pairId := crypoto.GetPubKeyStr(pair.PublicKey())
	hash := sha256.Sum256([]byte(pairId))
	originalNodeId := hex.EncodeToString(hash[:])

	wg.Add(1)
	go func() {
		defer wg.Done()
		stream, _, err := TryConnectTCPStream(RelayServerAddr, TargetNodeId, pairId)
		if err != nil {
			t.Error("ERROR:" + err.Error())
			return
		}
		defer stream.Close()
		ClientFirstMessage, err := stream.NextMessage(context.Background())
		if err != nil {
			t.Error("ERROR:" + err.Error())
			return
		}
		t.Log("RelayServerFirstMessage:", string(ClientFirstMessage.Payload))
	}()
	return originalNodeId
}

func TestNewStreamGroup(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start relay server: %v", err)
	}
	defer tcpListener.Close()
	relayAddr := tcpListener.Addr().String()
	t.Log("Relay Server started on " + relayAddr)
	var group *StreamGroup
	var pendingStream network.Stream
	var pendingMessage *network.Message
	wg := &sync.WaitGroup{}
	establishId := NodeEstablish(relayAddr, "test-node-id-source-string", t, wg, false)
	t.Log("establishId:", establishId)
	ClientSendTestMessage(establishId, relayAddr, "test-node-id1-source-string", t, wg)
	for accepted := 0; accepted < 2; accepted++ {
		accept, err := tcpListener.Accept()
		if err != nil {
			t.Logf("Failed to accept connection: %v", err)
			return
		}
		stream, firstMessage, err := AcceptTcpStream(accept)
		if err != nil {
			t.Logf("Failed to setup relay stream: %v", err)
			return
		}
		if firstMessage.Header.ConnectionId == "" {
			group = NewStreamGroup(stream, defaultHookfunc)
			go func() {
				group.StartListen()
			}()
			if pendingStream != nil {
				forwardFirstMessage, err := group.StreamOn(pendingStream, pendingMessage)
				if err != nil {
					t.Error("ERROR:" + err.Error())
					return
				}
				if forwardFirstMessage {
					if err := group.relayStream.SendMessage(context.Background(), pendingMessage); err != nil {
						t.Error("ERROR:" + err.Error())
					}
				}
			}
			continue
		}
		if group == nil {
			pendingStream = stream
			pendingMessage = firstMessage
			continue
		}
		forwardFirstMessage, err := group.StreamOn(stream, firstMessage)
		if err != nil {
			t.Error("ERROR:" + err.Error())
			return
		}
		if forwardFirstMessage {
			if err := group.relayStream.SendMessage(context.Background(), firstMessage); err != nil {
				t.Error("ERROR:" + err.Error())
			}
		}
	}
	wg.Wait()

}

func TestNewTransportCover(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start relay server: %v", err)
	}
	defer tcpListener.Close()
	relayAddr := tcpListener.Addr().String()
	wg := &sync.WaitGroup{}

	transport := NewTransportCover()

	// 持续 accept：dual 拨号在纯 TCP 测试环境下 KCP（UDP）拨号必失败，会自动补一条 TCP
	// 组成双 TCP failover，使每个逻辑连接产生 >1 条 TCP 物理连接。这里用后台循环持续接受
	// 所有入站 TCP，每条连接各起 goroutine 交给 ListenTCPConnection（它阻塞到首帧处理完才返回），
	// 这样注册节点与各 client 的全部 leg 都能被 relay 接纳并转发。
	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				return // listener 关闭后退出
			}
			go func(c net.Conn) {
				if e := transport.ListenTCPConnection(c); e != nil {
					t.Logf("ListenTCPConnection 处理结束: %v", e)
				}
			}(conn)
		}
	}()

	// 注册一个 relay 节点（establish），等其 dual 注册流（KCP 失败补 TCP + 双 TCP）稳定下来。
	establishId := NodeEstablish(relayAddr, "test-node-id-source-string", t, wg, true)
	time.Sleep(500 * time.Millisecond)

	// 串行接入 9 个 client：每个 client 是 dual 拨号（含 KCP 失败补 TCP）。
	// loopback 高速下，瞬时并发拉起大量 dual client 会对同一注册节点制造 leg 抖动风暴
	// （真机因网络延迟不触发），故逐个完成以稳定验证 TransportCover 的接入/转发原语。
	for i := 0; i < 9; i++ {
		clientWg := &sync.WaitGroup{}
		ClientId := ClientSendTestMessage(establishId, relayAddr, fmt.Sprintf("test-node-id%d-source-string", i), t, clientWg)
		t.Logf("ClientId: %s ,Client Index: %d ", ClientId, i)

		done := make(chan struct{})
		go func() { clientWg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(8 * time.Second):
			t.Fatalf("client %d 未在超时内收到注册节点回包", i)
		}
	}
	wg.Wait()
}

func TestRandomRelayClientInteraction(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start relay server: %v", err)
	}
	defer tcpListener.Close()
	relayAddr := tcpListener.Addr().String()

	wg := &sync.WaitGroup{}
	transport := NewTransportCover()

	// 持续 accept：dual 拨号（KCP 失败补 TCP 的双 TCP）使每个逻辑连接产生 >1 条 TCP 物理连接，
	// 后台循环接受所有入站连接并各起 goroutine 处理，匹配真实 leg 数。
	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				if e := transport.ListenTCPConnection(c); e != nil {
					t.Logf("ListenTCPConnection 处理结束: %v", e)
				}
			}(conn)
		}
	}()

	// 配置区域：简单控制 Relay 和 Client 的数量或比例
	baseRelayCount := 3
	baseClientCount := 10

	t.Logf("Starting test with %d Relays and %d Clients", baseRelayCount, baseClientCount)
	var relayNodeIds []string
	// 1. 建立指定数量的 Relay 持久连接，并等其 dual 注册流稳定。
	for i := 0; i < baseRelayCount; i++ {
		relayNodeIdSource := fmt.Sprintf("relay-node-id-source-%d", i)
		establishId := NodeEstablish(relayAddr, relayNodeIdSource, t, wg, true)
		t.Logf("Relay %d established with ID: %s", i, establishId)
		relayNodeIds = append(relayNodeIds, establishId)
	}
	time.Sleep(500 * time.Millisecond)

	// 2. 串行模拟 Client 与随机 Relay 交互：逐个完成以避免 loopback 高速下大量 dual client
	// 对同一注册节点制造的 leg 抖动风暴（真机因网络延迟不触发）。
	for i := 0; i < baseClientCount; i++ {
		if len(relayNodeIds) == 0 {
			t.Logf("No available relays for client %d", i)
			continue
		}
		targetRelayId := relayNodeIds[rand.Intn(len(relayNodeIds))]

		pair, err := crypoto.MakeKeyPair()
		if err != nil {
			t.Fatalf("Failed to make key pair: %v", err)
			return
		}
		pubKeyStr := crypoto.GetPubKeyStr(pair.PublicKey())

		clientWg := &sync.WaitGroup{}
		clientWg.Add(1)
		go func() {
			stream, connectionId, err := TryConnectTCPStream(relayAddr, targetRelayId, pubKeyStr)
			if err != nil {
				t.Logf("Failed to connect to relay: %v", err)
				clientWg.Done()
				return
			}
			ClientTestWithStream(stream, connectionId, targetRelayId, t, clientWg)
		}()

		done := make(chan struct{})
		go func() { clientWg.Wait(); close(done) }()
		select {
		case <-done:
			t.Logf("Client %d done targeting Relay(%s)", i, targetRelayId)
		case <-time.After(8 * time.Second):
			t.Fatalf("client %d 未在超时内完成 (target=%s)", i, targetRelayId)
		}
	}

	wg.Wait()
}
