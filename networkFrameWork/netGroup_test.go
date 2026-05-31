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
			t.Fatalf("Failed to register relay stream: %v", err.Error())
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
	establishId := NodeEstablish(relayAddr, "test-node-id-source-string", t, wg, true)
	//wg.Add(1)
	// 开始注册一个relay Connection
	accept, err := tcpListener.Accept()
	t.Logf("accept: %v", -1)
	if err != nil {
		t.Logf("Failed to accept connection: %v", err)
	}
	err = transport.ListenTCPConnection(accept)
	if err != nil {
		t.Fatalf("Failed to transport connection: %v", err)
		return
	}
	for i := 0; i < 9; i++ {
		ClientId := ClientSendTestMessage(establishId, relayAddr, fmt.Sprintf("test-node-id%d-source-string", i), t, wg)
		t.Logf("ClientId: %s ,Client Index: %d ", ClientId, i)
		accept, err = tcpListener.Accept()
		t.Logf("accept: %v", i)
		if err != nil {
			t.Logf("Failed to accept connection: %v", err)
		}
		err = transport.ListenTCPConnection(accept)
		if err != nil {
			t.Fatalf("Failed to transport connection: %v", err)
			return
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

	// 配置区域：简单控制 Relay 和 Client 的数量或比例
	baseRelayCount := 3
	baseClientCount := 10

	t.Logf("Starting test with %d Relays and %d Clients", baseRelayCount, baseClientCount)
	// 用于存储 Relay 节点的 ID，供 Client 随机选择
	var relayNodeIds []string
	// 1. 建立指定数量的 Relay 持久连接
	for i := 0; i < baseRelayCount; i++ {
		// 每个 Relay 使用不同的 NodeID Source 以区分
		relayNodeIdSource := fmt.Sprintf("relay-node-id-source-%d", i)
		establishId := NodeEstablish(relayAddr, relayNodeIdSource, t, wg, true)
		t.Logf("Relay %d established with ID: %s", i, establishId)

		// 将建立的 Relay ID 存入列表
		relayNodeIds = append(relayNodeIds, establishId)

		accept, err := tcpListener.Accept()
		if err != nil {
			t.Logf("Failed to accept relay connection %d: %v", i, err)
			continue
		}

		err = transport.ListenTCPConnection(accept)
		if err != nil {
			t.Fatalf("Failed to transport relay connection %d: %v", i, err)
		}
	}

	// 2. 模拟指定数量的 Client 节点与 Relay 交互
	for i := 0; i < baseClientCount; i++ {
		wg.Add(1)

		// 随机选择一个 Relay ID 作为目标
		targetRelayId := ""
		if len(relayNodeIds) > 0 {
			randomIndex := rand.Intn(len(relayNodeIds))
			targetRelayId = relayNodeIds[randomIndex]
		} else {
			// 如果没有可用的 Relay，跳过或报错，这里选择跳过并减少 wg
			t.Logf("No available relays for client %d", i)
			wg.Done()
			continue
		}

		pair, err := crypoto.MakeKeyPair()
		if err != nil {
			t.Fatalf("Failed to make key pair: %v", err)
			return
		}
		pubKeyStr := crypoto.GetPubKeyStr(pair.PublicKey())
		hash := sha256.Sum256([]byte(pubKeyStr))
		originalNodeId := hex.EncodeToString(hash[:])
		go func() {
			stream, connectionId, err := TryConnectTCPStream(relayAddr, targetRelayId, pubKeyStr)
			if err != nil {
				t.Logf("Failed to connect to relay: %v", err)
				return
			}
			ClientTestWithStream(stream, connectionId, targetRelayId, t, wg)
		}()

		// 使用随机选择的 targetRelayId 替换原来的固定 targetRelaySource

		t.Logf("Client %d started with ID: %s targeting Relay(%s)", i, originalNodeId, targetRelayId)
		//clientSource := fmt.Sprintf("client-node-id-source-%d", i)
		//ClientId := ClientSendTestMessage(targetRelayId, "127.0.0.1:9000", clientSource, t, wg)
		//t.Logf("Client %d started with ID: %s targeting Relay(%s)", i, ClientId, targetRelayId)
		accept, err := tcpListener.Accept()
		if err != nil {
			t.Logf("Failed to accept client connection %d: %v", i, err)
			wg.Done() // 平衡 wg.Add
			continue
		}

		err = transport.ListenTCPConnection(accept)
		if err != nil {
			t.Logf("Failed to transport client connection %d: %v", i, err)
			// 这里不直接 fatal，因为可能是单个客户端失败，允许其他继续
		}
	}

	wg.Wait()

	t.Log("Test finished: All clients completed.")
}
