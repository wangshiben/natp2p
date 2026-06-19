package networkFrameWork

import (
	"bnfs_p2p/crypoto"
	"bnfs_p2p/network"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

const relayHashRoute = "/hash-chain"

type relayTestIdentity struct {
	keyPair     *ecdh.PrivateKey
	publicKey   string
	nodeID      string
	nodeIDHash  string
	displayName string
}

type relayHashSession struct {
	clientNodeID      string
	startHash         string
	nextInboundCount  int
	communications    int
	communicationFlow []string
}

type relayHashResponder struct {
	serverNodeHash string

	mu       sync.Mutex
	sessions map[string]*relayHashSession
}

type hashChainClientResult struct {
	name           string
	connectionID   string
	nodeID         string
	startHash      string
	finalHash      string
	communications int
	chain          []string
}

func newRelayHashResponder(serverNodeHash string) *relayHashResponder {
	return &relayHashResponder{
		serverNodeHash: serverNodeHash,
		sessions:       make(map[string]*relayHashSession),
	}
}

func (r *relayHashResponder) bootstrap(connectionID, clientSeed string) {
	clientNodeID := hashHex(clientSeed)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[connectionID] = &relayHashSession{
		clientNodeID:     clientNodeID,
		startHash:        hashHex(clientNodeID),
		nextInboundCount: 1,
	}
}

func (r *relayHashResponder) respond(connectionID, payload string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	session := r.sessions[connectionID]
	if session == nil {
		return "", fmt.Errorf("connection %s was not bootstrapped", connectionID)
	}

	expectedInbound := verifyRelayHashChain(session.startHash, r.serverNodeHash, payload, session.nextInboundCount)
	if payload != expectedInbound {
		return "", fmt.Errorf(
			"connection %s hash mismatch at communication %d: got %s want %s",
			connectionID,
			session.nextInboundCount,
			payload,
			expectedInbound,
		)
	}

	session.communicationFlow = append(session.communicationFlow, payload)
	session.communications++

	responseCount := session.nextInboundCount + 1
	responseHash := verifyRelayHashChain(session.startHash, r.serverNodeHash, "", responseCount)
	session.communicationFlow = append(session.communicationFlow, responseHash)
	session.communications++
	session.nextInboundCount += 2

	return responseHash, nil
}

func (r *relayHashResponder) Snapshot(connectionID string) ([]string, int, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	session := r.sessions[connectionID]
	if session == nil {
		return nil, 0, false
	}

	chain := append([]string(nil), session.communicationFlow...)
	return chain, session.communications, true
}

func (r *relayHashResponder) SessionCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}

//  relay_hash_chain_test.go:306: device2 NODEId: 04cdd7fe5a016cfade4ae953f0164d43662d77f8d744284bc84588d0c217056a48157ee15da70d00d3f64d1e00a8112aed8513be02791f56b4bd421329c69bb6fc
//    relay_hash_chain_test.go:307: device2 nodeId: 818901bbe315286a34143b9d41e6ce567fed4d789ac177e1d7764637622c2ec1
//    relay_hash_chain_test.go:308: device2 nodeId hash: c13913aa8d102e17bba23ecb128abd4c3e4acbdc2b92fe4f646b35a7b7a4c1af
//    relay_hash_chain_test.go:309: device3-a NODEId: 044211ebe205fb235f49bc639944a667cda724b113665faab6d4b391ea937c5a9e7d31144d4b37e02a7df6beb8bf84489ff039cc1c8e9c4b8cfbc12ee419db4fc4
//    relay_hash_chain_test.go:310: device3-a nodeId: 6e186665339dda4b02170b0d173f239c37b4665fbf71f22a3a3187cadd4bc25c
//    relay_hash_chain_test.go:311: device3-a NODEId hash: 6e186665339dda4b02170b0d173f239c37b4665fbf71f22a3a3187cadd4bc25c
//    relay_hash_chain_test.go:312: device3-a nodeId hash: 30810f42a13c89245d2d6661a790716ba390e71fdce4ebc87a766668168b732a
//    relay_hash_chain_test.go:313: device3-b NODEId: 04c8ec8af850ada7615f870b87b72f072e4a4867d53a5d1d4d31b6aefc861a0698482a289fd634d050c9547f4d86545329ad50f17d96fbe5c0f3c50beb89cd151b
//    relay_hash_chain_test.go:314: device3-b nodeId: cbb7b2ddc659959f2b24cf309caf5f4748e3d4232fd3ab4441bbc72bc86efbd7
//    relay_hash_chain_test.go:315: device3-b NODEId hash: cbb7b2ddc659959f2b24cf309caf5f4748e3d4232fd3ab4441bbc72bc86efbd7
//    relay_hash_chain_test.go:316: device3-b nodeId hash: c3b1b41d779c00db1af6cf224a4c711c271d0d6eb8a17593344a38ecd4e76c06
//    relay_hash_chain_test.go:358: device3-b communication count: 42
//    relay_hash_chain_test.go:359: device3-b final hash: 67e240394d9b5f7b832b11e1de4b958972a3f89bf6cc30604966012c935a1529
//    relay_hash_chain_test.go:360: device3-b hash chain: 1:c3b1b41d779c...6c06 -> 2:4e13d63ff86c...3a71 -> 3:d439022301fb...b3f6 -> 4:18c38a4be286...f837 -> 5:fc170eaff3b0...8cbd -> 6:765c326e1715...e9a6 -> 7:bc4b06a32824...3e0b -> 8:972fbe505dd4...8e6a -> 9:97e0e458f555...b6b3 -> 10:871f20fb31dc...fda4 -> 11:0476613995bd...8c3d -> 12:5b4d3929ab0b...01b8 -> 13:7bdd2cdef26b...a288 -> 14:2a9872319608...e692 -> 15:5cb77cc64fdf...a002 -> 16:173ffb563b40...8180 -> 17:6059b449ae59...d5da -> 18:b1192638a8e7...14f9 -> 19:4ddb866383a6...1bf8 -> 20:f6cb210a51db...d921 -> 21:e4b27d1fc3d5...2a5b -> 22:6422d60e5630...5172 -> 23:9ad8ae478db6...ade5 -> 24:936e5d4570cf...db71 -> 25:77e7dfe4912a...9aaf -> 26:ad5e57502e9e...318f -> 27:a5dbee7aa2ac...80cb -> 28:a338805e68be...85df -> 29:852d1f844174...d309 -> 30:479a8c89d06d...9bae -> 31:47ade7266e8c...392a -> 32:23a9f1145fd5...cb56 -> 33:a25a023df635...09c4 -> 34:4d0023ecf615...1c73 -> 35:fa1c31eeadd2...c48a -> 36:339b2c2514ed...384d -> 37:b344d641fce3...2075 -> 38:e6a60d9358e2...d48f -> 39:0721ab94ce73...a67a -> 40:85a42bd83dfd...3269 -> 41:e9a63c338881...a250 ->
//   42:67e240394d9b...1529
//    relay_hash_chain_test.go:358: device3-a communication count: 42
//    relay_hash_chain_test.go:359: device3-a final hash: 40162f15c7e0457c4dcd110b56800acc88354af15690888bfe5bdc305a6254e5
//    relay_hash_chain_test.go:360: device3-a hash chain: 1:30810f42a13c...732a -> 2:97d8a550f43d...9f5c -> 3:3c15dcb4544a...97ca -> 4:95896c288e63...0fe3 -> 5:16c30019eb6e...08b6 -> 6:ecef9b1039f3...4dc8 -> 7:26e90b6ac71e...65e7 -> 8:9824d483d77d...8f16 -> 9:d45895671756...b645 -> 10:5f3c68e5e485...f2ac -> 11:761d2163c51e...f47d -> 12:8fade462ff3b...34b5 -> 13:a74c571f135e...31cb -> 14:296e42b05cec...bb56 -> 15:dd1660a35b26...24eb -> 16:a7ae8e9854c2...e8e2 -> 17:267d2c2e8fda...b63d -> 18:86b17b883c67...3ace -> 19:40e4603bae1f...5f3c -> 20:c6d8f06031f0...1855 -> 21:0861b2e17c90...0ad3 -> 22:d420b2185007...233b -> 23:b63a09d39e02...8695 -> 24:c60a224e2e70...50a1 -> 25:4988a60a4db1...8bf3 -> 26:998b9e818d7f...cc13 -> 27:835ab3bbba82...a0f9 -> 28:2f4b59377a9f...40e0 -> 29:d434fa141a35...76d0 -> 30:60057b7922af...96c4 -> 31:cc6ab3282789...ba8c -> 32:d5bf6c072244...4c56 -> 33:e6fd2d7c1c98...c045 -> 34:f9c413dd2a24...eba7 -> 35:86cdd211563f...edc3 -> 36:69d5e0904bad...2370 -> 37:a18b8c8d7ed4...7b8d -> 38:cb87cfa4d84e...da2e -> 39:7f225090e5f3...1c72 -> 40:0920e3a2ce38...69d5 -> 41:331c8f82ef80...43fc
//   -> 42:40162f15c7e0...54e5

func TestConnectionResource_Close(t *testing.T) {
	node2 := "c13913aa8d102e17bba23ecb128abd4c3e4acbdc2b92fe4f646b35a7b7a4c1af"
	node3 := "c3b1b41d779c00db1af6cf224a4c711c271d0d6eb8a17593344a38ecd4e76c06"
	chainResult := verifyRelayHashChain(node3, node2, node3, 42)
	fmt.Printf("chainResult: %s\n", chainResult)
}

func TestRelayHashChainIsolation(t *testing.T) {
	// 用例耗时 1 分钟（持续往返哈希），go test -short 模式下跳过
	if testing.Short() {
		t.Skip("skipping 1-minute relay hash chain isolation test in short mode")
	}

	// 测试参数：监听地址、整体持续时长、客户端发送节奏、单次 IO 超时
	// 监听地址使用 127.0.0.1:0 让系统自动分配空闲端口，避免与本机其他服务（如 docker）端口冲突
	const (
		relayListenAddr = "127.0.0.1:0"
		testDuration    = time.Minute
		clientSendPace  = time.Second
		ioTimeout       = 5 * time.Second
	)

	// 1. 启动 Relay 服务端：监听 TCP 端口，接收所有客户端 / Server 节点的接入
	tcpListener, err := net.Listen("tcp", relayListenAddr)
	if err != nil {
		t.Fatalf("Failed to start relay server: %v", err)
	}
	defer tcpListener.Close()

	// 客户端拨号使用 listener 实际分配到的地址
	relayAddr := tcpListener.Addr().String()

	// 用 TransportCover 把每条 TCP 连接转换成 Stream，并维护 NodeId -> StreamGroup 映射
	transport := NewTransportCover()
	go func() {
		for {
			conn, err := tcpListener.Accept()
			if err != nil {
				// listener 被 Close 后 Accept 返回错误，此时正常退出 accept 循环
				return
			}
			go func(c net.Conn) {
				if err := transport.ListenTCPConnection(c); err != nil {
					// 主动关闭 listener 引发的 "use of closed network connection" 不算异常
					if !strings.Contains(err.Error(), "use of closed network connection") {
						t.Logf("Failed to transport connection: %v", err)
					}
				}
			}(conn)
		}
	}()

	// 给整个用例设置一个上界，防止任何环节卡死把 go test 整体挂住
	ctx, cancel := context.WithTimeout(context.Background(), testDuration+30*time.Second)
	defer cancel()

	// 2. 准备 device2 身份并以 "Server 节点" 角色注册到 Relay（ConnectionId 为空表示注册 relayStream）
	device2Identity, err := newRelayTestIdentity("device2")
	if err != nil {
		t.Fatalf("create device2 identity: %v", err)
	}
	serverStream, err := registerRelayTCPOnly(device2Identity, relayAddr)
	if err != nil {
		t.Fatalf("register relay server: %v", err)
	}
	defer serverStream.Close()

	// 校验 Stream 上报的 NodeId 与本地身份一致，避免后续会话用错 key
	serverNodeID := serverStream.NodeId()
	serverNodeHash := device2Identity.nodeIDHash
	if serverNodeID != device2Identity.nodeID {
		t.Fatalf("device2 nodeId mismatch: stream=%s identity=%s", serverNodeID, device2Identity.nodeID)
	}
	// 等到 TransportCover 把 device2 注册进 StreamGroup 后，客户端才能寻址过来
	if err := waitForRelayGroup(transport, serverNodeID, 5*time.Second); err != nil {
		t.Fatalf("wait for relay group: %v", err)
	}

	// 3. 启动应答协程：消费 device2 收到的客户端消息，按哈希链规则回 ACK
	responder := newRelayHashResponder(serverNodeHash)
	responderErrCh := make(chan error, 1)
	go runRelayHashResponder(ctx, serverStream, responder, serverNodeID, ioTimeout, responderErrCh)

	// 4. 准备两个客户端身份 device3-a / device3-b，用来验证两条会话的哈希链相互隔离
	device3AIdentity, err := newRelayTestIdentity("device3-a")
	if err != nil {
		t.Fatalf("create device3-a identity: %v", err)
	}
	device3BIdentity, err := newRelayTestIdentity("device3-b")
	if err != nil {
		t.Fatalf("create device3-b identity: %v", err)
	}
	clientIdentities := []*relayTestIdentity{device3AIdentity, device3BIdentity}

	// 客户端结果通过 mutex 保护的 map 收集；任何一个客户端出错则走 clientErrCh
	wg := &sync.WaitGroup{}
	resultMu := sync.Mutex{}
	results := make(map[string]*hashChainClientResult, len(clientIdentities))
	clientErrCh := make(chan error, len(clientIdentities))

	// 5. 并发拉起所有客户端会话，各自跑满 testDuration 才算完成
	startedAt := time.Now()
	for _, identity := range clientIdentities {
		identity := identity // 捕获循环变量，避免所有 goroutine 共享同一个 identity
		wg.Add(1)
		go func() {
			defer wg.Done()
			result, err := runRelayHashClient(ctx, relayAddr, serverNodeID, serverNodeHash, identity, testDuration, clientSendPace, ioTimeout)
			if err != nil {
				clientErrCh <- fmt.Errorf("%s: %w", identity.displayName, err)
				return
			}
			resultMu.Lock()
			results[result.name] = result
			resultMu.Unlock()
		}()
	}

	// 把 wg.Wait 转成 channel，方便和 errCh / ctx.Done 在同一个 select 里竞争
	waitDone := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitDone)
	}()

	// 6. 等待所有客户端正常结束，或者任一侧报错 / 用例超时
	select {
	case <-waitDone:
	case err := <-responderErrCh:
		t.Fatalf("relay responder error: %v", err)
	case err := <-clientErrCh:
		t.Fatalf("client error: %v", err)
	case <-ctx.Done():
		t.Fatalf("relay hash chain test timeout: %v", ctx.Err())
	}

	// waitDone 触发但 result 数量不够，说明有客户端在写 errCh 之前已退出，需当作失败
	if len(results) != len(clientIdentities) {
		t.Fatalf("expected %d client results, got %d", len(clientIdentities), len(results))
	}

	// 防御性校验：实际跑的时长必须 >= testDuration，避免有人误改 duration 让用例提前结束
	if elapsed := time.Since(startedAt); elapsed < testDuration {
		t.Fatalf("hash communication ended too early: ran %s, need at least %s", elapsed, testDuration)
	}

	// Relay 端记录的会话数应当与客户端数对齐，少一个意味着隔离前的会话建立就异常了
	if responder.SessionCount() != len(clientIdentities) {
		t.Fatalf("expected %d relay sessions, got %d", len(clientIdentities), responder.SessionCount())
	}

	// 7. 输出节点身份信息，方便失败时复现哈希链
	t.Logf("device2 NODEId: %s", device2Identity.publicKey)
	t.Logf("device2 nodeId: %s", device2Identity.nodeID)
	t.Logf("device2 nodeId hash: %s", device2Identity.nodeIDHash)
	t.Logf("device3-a NODEId: %s", device3AIdentity.publicKey)
	t.Logf("device3-a nodeId: %s", device3AIdentity.nodeID)
	t.Logf("device3-a NODEId hash: %s", device3AIdentity.nodeID)
	t.Logf("device3-a nodeId hash: %s", device3AIdentity.nodeIDHash)
	t.Logf("device3-b NODEId: %s", device3BIdentity.publicKey)
	t.Logf("device3-b nodeId: %s", device3BIdentity.nodeID)
	t.Logf("device3-b NODEId hash: %s", device3BIdentity.nodeID)
	t.Logf("device3-b nodeId hash: %s", device3BIdentity.nodeIDHash)

	// 8. 逐个客户端做最终校验：本地链长度自洽 -> 重新推导终值 -> 与 Relay 端记录的链逐项比对
	finalHashes := make(map[string]string, len(results))
	for _, result := range results {
		// communications 计数应当与 chain 长度一一对应，否则说明发送/记录路径有遗漏
		if result.communications != len(result.chain) {
			t.Fatalf("%s communication count mismatch: count=%d chain=%d", result.name, result.communications, len(result.chain))
		}

		// 用同样的递推规则重算终态哈希，验证客户端持有的 finalHash 没有被篡改
		calculated := verifyRelayHashChain(result.startHash, serverNodeHash, result.finalHash, result.communications)
		if calculated != result.finalHash {
			t.Fatalf(
				"%s final hash mismatch: got %s want %s at communication %d",
				result.name,
				result.finalHash,
				calculated,
				result.communications,
			)
		}

		// 取 Relay 端记录的同一会话快照，逐项比对——任何错位都意味着两条会话之间发生了串扰
		serverChain, serverCount, ok := responder.Snapshot(result.connectionID)
		if !ok {
			t.Fatalf("missing relay session snapshot for %s", result.name)
		}
		if serverCount != result.communications {
			t.Fatalf("%s relay communication count mismatch: relay=%d client=%d", result.name, serverCount, result.communications)
		}
		if len(serverChain) != len(result.chain) {
			t.Fatalf("%s relay chain length mismatch: relay=%d client=%d", result.name, len(serverChain), len(result.chain))
		}
		for idx := range serverChain {
			if serverChain[idx] != result.chain[idx] {
				t.Fatalf(
					"%s relay chain mismatch at step %d: relay=%s client=%s",
					result.name,
					idx+1,
					serverChain[idx],
					result.chain[idx],
				)
			}
		}

		finalHashes[result.name] = result.finalHash
		t.Logf("%s communication count: %d", result.name, result.communications)
		t.Logf("%s final hash: %s", result.name, result.finalHash)
		t.Logf("%s hash chain: %s", result.name, formatHashChain(result.chain))
	}

	// 9. 隔离性的最终断言：两条会话的终态哈希必须不同，否则证明会话间发生了交叉污染
	if finalHashes["device3-a"] == finalHashes["device3-b"] {
		t.Fatalf("two client sessions produced the same final hash, isolation check failed")
	}
}

// runRelayHashResponder 运行在 device2 一侧，循环读取 Relay 转发过来的客户端消息，
// 按"收到一条 -> 校验哈希 -> 算出下一跳 -> 回写"的方式维持每条会话的哈希链。
func runRelayHashResponder(
	parent context.Context,
	stream network.Stream,
	responder *relayHashResponder,
	serverNodeID string,
	ioTimeout time.Duration,
	errCh chan<- error,
) {
	for {
		// 从 stream 拉下一条非 KeepAlive 的消息；parent 已取消时静默退出，避免污染 errCh
		message, err := nextNonKeepAliveMessage(parent, stream, ioTimeout)
		if err != nil {
			if parent.Err() != nil {
				return
			}
			errCh <- err
			return
		}

		// 没有 ConnectionId 的消息属于框架层控制帧，跳过
		if message.Header.ConnectionId == "" {
			continue
		}

		// RouteName 为空 = 客户端首包，这里只做 session 注册，不写回响应
		if message.Header.RouteName == "" {
			responder.bootstrap(message.Header.ConnectionId, string(message.Payload))
			continue
		}

		// 非预期的路由直接报错退出，避免误把其它流量纳入哈希链统计
		if message.Header.RouteName != relayHashRoute {
			errCh <- fmt.Errorf("unexpected route %s on connection %s", message.Header.RouteName, message.Header.ConnectionId)
			return
		}

		// 校验客户端这次发来的哈希是否落在链上正确位置，并算出本端下一步要回的哈希
		responseHash, err := responder.respond(message.Header.ConnectionId, string(message.Payload))
		if err != nil {
			errCh <- err
			return
		}

		// 回写响应：路由 / NodeId / ConnectionId 必须原样回填，框架据此把消息转发给正确的客户端
		response := &network.Message{
			Header: &network.Header{
				RouteName:     relayHashRoute,
				NodeId:        serverNodeID,
				NodeIdVersion: 1,
				ConnectionId:  message.Header.ConnectionId,
			},
			Payload: []byte(responseHash),
		}
		if err := sendMessageWithTimeout(parent, stream, response, ioTimeout); err != nil {
			if parent.Err() != nil {
				return
			}
			errCh <- err
			return
		}
	}
}

// runRelayHashClient 运行在 device3-a / device3-b 一侧，
// 持续 duration 时长，按 pace 节奏与 device2 维持一条独立的哈希链，最终把整条链汇报回主测试。
func runRelayHashClient(
	parent context.Context,
	relayAddr, targetNodeID, targetNodeHash string,
	identity *relayTestIdentity,
	duration, pace, ioTimeout time.Duration,
) (*hashChainClientResult, error) {
	// 通过 Relay 拨向 device2，连接成功后会拿到本会话的 connectionID
	stream, connectionID, err := connectRelayTCPOnly(relayAddr, targetNodeID, identity)
	if err != nil {
		return nil, err
	}
	defer stream.Close()

	// startHash 是哈希链的起点，固定为本端 nodeId 的哈希；同时作为 chain 的第 1 项
	startHash := identity.nodeIDHash
	result := &hashChainClientResult{
		name:         identity.displayName,
		connectionID: connectionID,
		nodeID:       identity.nodeID,
		startHash:    startHash,
		chain:        []string{startHash},
	}

	// 首包：把 startHash 作为 payload 发给 device2，触发对端 bootstrap 该 session
	initial := &network.Message{
		Header: &network.Header{
			RouteName:     relayHashRoute,
			NodeId:        targetNodeID,
			NodeIdVersion: 1,
			ConnectionId:  connectionID,
		},
		Payload: []byte(startHash),
	}
	if err := sendMessageWithTimeout(parent, stream, initial, ioTimeout); err != nil {
		return nil, err
	}
	result.communications = 1

	startedAt := time.Now()
	for {
		// 读对端响应：communications 自增并按链上位置重算期望哈希做校验
		response, err := nextNonKeepAliveMessage(parent, stream, ioTimeout)
		if err != nil {
			return nil, err
		}
		receivedHash := string(response.Payload)
		result.communications++

		expected := verifyRelayHashChain(startHash, targetNodeHash, receivedHash, result.communications)
		if receivedHash != expected {
			return nil, fmt.Errorf(
				"unexpected response hash at communication %d: got %s want %s",
				result.communications,
				receivedHash,
				expected,
			)
		}
		result.chain = append(result.chain, receivedHash)

		// 跑满预定时长就退出，并以最后一次收到的哈希作为 finalHash
		if time.Since(startedAt) >= duration {
			result.finalHash = receivedHash
			return result, nil
		}

		// 节流：要么等到 pace，要么父 context 被取消时立即退出
		select {
		case <-parent.Done():
			return nil, parent.Err()
		case <-time.After(pace):
		}

		// 算出本端下一步要发的哈希，并把它写进链；与 device2 同算法保证两端结果一致
		nextHash := verifyRelayHashChain(startHash, targetNodeHash, "", result.communications+1)
		request := &network.Message{
			Header: &network.Header{
				RouteName:     relayHashRoute,
				NodeId:        targetNodeID,
				NodeIdVersion: 1,
				ConnectionId:  connectionID,
			},
			Payload: []byte(nextHash),
		}
		if err := sendMessageWithTimeout(parent, stream, request, ioTimeout); err != nil {
			return nil, err
		}

		result.communications++
		result.chain = append(result.chain, nextHash)
	}
}

// registerRelayTCPOnly 让 identity 以 "Server 节点" 身份接入 Relay：
// ConnectionId 留空告诉 TransportCover 这是注册流，而不是普通客户端会话。
func registerRelayTCPOnly(identity *relayTestIdentity, relayAddr string) (network.Stream, error) {
	firstMessage := &network.Message{
		Header: &network.Header{
			RouteName:     "",
			NodeId:        identity.nodeID,
			NodeIdVersion: 1,
			ConnectionId:  "",
		},
		Payload: []byte(identity.publicKey),
	}
	return clientStream(firstMessage, relayAddr, identity.nodeID, "", false)
}

// connectRelayTCPOnly 让 identity 作为客户端接入 Relay 并寻址 targetNodeID：
// 这里生成一个新的 connectionID 作为本会话的唯一标识，后续所有消息都用它做关联。
func connectRelayTCPOnly(relayAddr, targetNodeID string, identity *relayTestIdentity) (network.Stream, string, error) {
	connectionID := uuid.New().String()
	firstMessage := &network.Message{
		Header: &network.Header{
			RouteName:     "",
			NodeId:        targetNodeID,
			NodeIdVersion: 1,
			ConnectionId:  connectionID,
		},
		Payload: []byte(identity.publicKey),
	}
	stream, err := clientStream(firstMessage, relayAddr, identity.nodeID, connectionID, false)
	if err != nil {
		return nil, "", err
	}
	return stream, connectionID, nil
}

// waitForRelayGroup 轮询 transport.StreamGroup，直到 nodeID 对应的 group 完成注册或超时。
// Server 节点 register 之后并非立刻进入 map，这里给客户端拨号留出一个就绪窗口。
func waitForRelayGroup(transport *TransportCover, nodeID string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		transport.lock.RLock()
		_, ok := transport.StreamGroup[nodeID]
		transport.lock.RUnlock()
		if ok {
			return nil
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("relay group %s not ready after %s", nodeID, timeout)
}

// nextNonKeepAliveMessage 读取一条业务消息并自动跳过 KeepAlive 心跳，
// 避免心跳被算进哈希链通信计数里。
func nextNonKeepAliveMessage(parent context.Context, stream network.Stream, timeout time.Duration) (*network.Message, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	for {
		message, err := stream.NextMessage(ctx)
		if err != nil {
			return nil, err
		}
		if message.Header.RouteName == KeepAliveRoute {
			continue
		}
		return message, nil
	}
}

func sendMessageWithTimeout(parent context.Context, stream network.Stream, message *network.Message, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	return stream.SendMessage(ctx, message)
}

func verifyRelayHashChain(startNodeHash, peerNodeHash, finalHash string, communicationCount int) string {
	_ = finalHash
	if communicationCount <= 0 {
		return ""
	}

	current := startNodeHash
	for step := 2; step <= communicationCount; step++ {
		if step%2 == 0 {
			current = hashHex(current + peerNodeHash)
			continue
		}
		current = hashHex(current + startNodeHash)
	}
	return current
}

func hashHex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func newRelayTestIdentity(displayName string) (*relayTestIdentity, error) {
	keyPair, err := crypoto.MakeKeyPair()
	if err != nil {
		return nil, err
	}
	publicKey := crypoto.GetPubKeyStr(keyPair.PublicKey())
	nodeID := hashHex(publicKey)
	return &relayTestIdentity{
		keyPair:     keyPair,
		publicKey:   publicKey,
		nodeID:      nodeID,
		nodeIDHash:  hashHex(nodeID),
		displayName: displayName,
	}, nil
}

func formatHashChain(chain []string) string {
	parts := make([]string, 0, len(chain))
	for idx, value := range chain {
		parts = append(parts, fmt.Sprintf("%d:%s", idx+1, shortHash(value)))
	}
	return strings.Join(parts, " -> ")
}

func shortHash(value string) string {
	if len(value) <= 16 {
		return value
	}
	return value[:12] + "..." + value[len(value)-4:]
}
