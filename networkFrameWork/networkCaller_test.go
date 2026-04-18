package networkFrameWork

import (
	"bnfs_p2p/crypoto"
	"bnfs_p2p/network"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

func RelayClientTest(t *testing.T) string {
	pair, err := crypoto.MakeKeyPair()
	time.Sleep(1 * time.Second)
	if err != nil {
		t.Fatalf("生成密钥对失败: %v", err)
		return ""
	}
	pubKeyStr := crypoto.GetPubKeyStr(pair.PublicKey())
	hash := sha256.Sum256([]byte(pubKeyStr))
	originalNodeId := hex.EncodeToString(hash[:])
	stream, err := TryRegisterRelayStream(pubKeyStr, "127.0.0.1:9000")
	if err != nil {
		return ""
	}
	go func() {
		message, err := stream.NextMessage()
		if err != nil {
			return
		}
		data, err := json.Marshal(message)
		if err != nil {
			return
		}
		t.Logf("[系统] 收到消息: %s\n", data)
		tcpStream := stream.(*TcpStream)
		hash := sha256.Sum256(message.Payload)
		originalNodeId := hex.EncodeToString(hash[:])
		ClientStream := &TcpStream{
			nodeId:       originalNodeId,
			connection:   tcpStream.connection,
			lock:         sync.Mutex{},
			connectionId: message.Header.ConnectionId,
		}

		crypto, err := crypoto.NewTLSCrypto(ClientStream, pair)

		if err != nil {
			t.Errorf("NewTLSCrypto err: %v", err)
			return
		}
		t.Log("RelayClientTest NewTLSCrypto success")
		defer ClientStream.Close()
		t.Log("I'm waiting for Message")
		message, err = ClientStream.NextMessage()
		marshal, _ := json.Marshal(message)
		t.Logf("I'm got a Message %s,\n %v", marshal, err)
		if err != nil {
			t.Errorf("NextMessage err: %v", err)
			ClientStream.Close()
			return
		}
		t.Logf("[系统] 收到消息: %v\n", message.Payload)
		decrypt, err := crypto.Decrypt(message.Payload)
		if err != nil {

			return
		}
		t.Logf("[系统] 收到消息: %s \n", decrypt)

	}()
	return originalNodeId
}

func ClientTest(RelayNodeId string, t *testing.T) (string, string, error) {
	time.Sleep(2 * time.Second)
	pair, err := crypoto.MakeKeyPair()
	if err != nil {
		t.Fatalf("生成密钥对失败: %v", err)
		return "", "", err
	}
	pubKeyStr := crypoto.GetPubKeyStr(pair.PublicKey())
	hash := sha256.Sum256([]byte(pubKeyStr))
	originalNodeId := hex.EncodeToString(hash[:])
	stream, connectionId, err := TryConnectTCPStream("127.0.0.1:9000", RelayNodeId, pubKeyStr)
	if err != nil {
		return "", "", err
	}
	//header := &network.Header{
	//	RouteName:     "",
	//	NodeId:        RelayNodeId,
	//	NodeIdVersion: 1,
	//	PayLoadLength: 0,
	//	ConnectionId:  connectionId,
	//	OriginData:    nil,
	//}
	//body := &network.Message{
	//	Header:  header,
	//	Payload: []byte(pubKeyStr),
	//}
	//stream.SendMessage(context.Background(), body)

	go func() {
		crypto, err := crypoto.NewTLSCrypto(stream, pair)
		t.Log("ClientTest NewTLSCrypto success")
		defer stream.Close()
		if err != nil {
			t.Errorf("NewTLSCrypto err: %v", err)
			return
		}
		encrypt, err := crypto.Encrypt([]byte("这是来自客户端的消息"))
		if err != nil {
			t.Errorf("加密失败: %v", err)
			return
		}
		Message := network.Message{
			Header: &network.Header{
				ConnectionId:  connectionId,
				NodeId:        RelayNodeId,
				NodeIdVersion: 1,
				RouteName:     "route1",
			},
			Payload: encrypt,
		}
		t.Log("Try send Message to relayStream")
		err = stream.SendMessage(t.Context(), &Message)
		t.Log("Success send Message to relayStream")
		if err != nil {
			t.Errorf("发送消息失败: %v", err)
			return
		}

	}()
	return originalNodeId, connectionId, nil
}

func TestNewTLSCrypto(t *testing.T) {
	t.Log("=== 测试 NewTLSCrypto ===")

	starter := NewRelayStarter(":9000")

	go func() {
		time.Sleep(1 * time.Second)
		RelayId := RelayClientTest(t)
		t.Logf("[系统] 中转服务器启动成功，监听端口 %d", 9000)
		t.Logf("[系统] 目标节点ID为 %s", RelayId)
		ClientId, connectionId, err := ClientTest(RelayId, t)
		if err != nil {
			t.Errorf("ClientTest err: %v", err)
			return
		}
		t.Logf("客户端连接成功 本次连接的连接ID为 %s 节点ID 为 %s", connectionId, ClientId)
	}()
	go func() {
		time.Sleep(10 * time.Second)
		starter.Close()
	}()
	starter.StartListen()

}

type TestData struct {
	Data []byte `json:"data"`
}

func TestTryConnectTCPStream(t *testing.T) {
	jsonStr := "{\"Data\":\"4GFwsR9XFRkyb/9Hn14zNpQRFE4V/f1hLIDlnff6LLPR/EvRmSW6ma6PHZiamB4mDeynjRYfVsfipg==\"}"
	message := &TestData{}
	err := json.Unmarshal([]byte(jsonStr), message)
	if err != nil {
		panic(err)
	}
	result := message.Data
	t.Logf("%v", result)
	t.Log(string(result))
	sprintf := fmt.Sprintf("%s", result)
	t.Log(sprintf)
	t.Logf("bad base64: %s", result)
	t.Log("test done")
}
