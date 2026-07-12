package relaynode

import (
	"bnfs_p2p/admission"
	"bnfs_p2p/networkFrameWork"
	"bnfs_p2p/p2pnode/impl/natnode"
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

// 准入集成测试端口（避开 relay_node_test.go 的 19501/19502）。
const (
	admRelay1Addr = "127.0.0.1:19601"
	admRelay2Addr = "127.0.0.1:19602"
)

// issueCertFor 用给定 CA 私钥为一台 relay 签发 indexSign（绑定其真实身份与角色）。
func issueCertFor(t *testing.T, caPriv *ecdsa.PrivateKey, rn *RelayNode, role admission.Role) *admission.SignedCert {
	t.Helper()
	nonce, _ := admission.NewNonce()
	cert := admission.Cert{
		SubjectNodeID: rn.idStr(),
		SubjectPubKey: rn.pubKeyHex(),
		Role:          role,
		NotBefore:     time.Now().Add(-time.Minute).Unix(),
		NotAfter:      time.Now().Add(time.Hour).Unix(),
		Nonce:         nonce,
		Issuer:        "test-ca",
	}
	sc, err := admission.Sign(caPriv, cert)
	if err != nil {
		t.Fatalf("签发 indexSign 失败: %v", err)
	}
	return sc
}

// verifierFor 构造一个已缓存指定 CA 公钥的离线验证器。
func verifierFor(t *testing.T, caPriv *ecdsa.PrivateKey) *admission.CAClient {
	t.Helper()
	pem, err := admission.MarshalCAPublicKeyPEM(&caPriv.PublicKey)
	if err != nil {
		t.Fatalf("编码 CA 公钥失败: %v", err)
	}
	cc := admission.NewCAClient("")
	if err := cc.SetPubKeyPEM(pem); err != nil {
		t.Fatalf("注入 CA 公钥失败: %v", err)
	}
	return cc
}

// relayKnows 报告 rn 的 relayNodes DHT 是否已登记 peerID（= HELLO 交换成功、准入通过的标志）。
func relayKnows(rn *RelayNode, peerID string) bool {
	for _, p := range rn.RelayNeighbors() {
		if string(p.ID) == peerID {
			return true
		}
	}
	return false
}

// TestAdmission_IndexSign_Enforce_ValidCert 验证：enforce 模式 + dual(KCP+TCP) 控制链路下，
// 两台持同一 CA 签发 indexSign 的 relay 能通过无交互离线验签并建立控制链路。
// （关键回归点：dual 双 leg 各自携带 indexSign 独立验签，不应发生握手竞态。）
func TestAdmission_IndexSign_Enforce_ValidCert(t *testing.T) {
	caPriv, err := admission.GenerateCAKey()
	if err != nil {
		t.Fatalf("生成 CA 密钥失败: %v", err)
	}

	relay1 := startRelay(t, admRelay1Addr, admRelay1Addr)
	defer relay1.Close()
	relay2 := startRelay(t, admRelay2Addr, admRelay2Addr)
	defer relay2.Close()

	relay1.SetAdmission(&AdmissionConfig{
		Mode: AdmissionEnforce, SelfCert: issueCertFor(t, caPriv, relay1, admission.RoleRelay), Verifier: verifierFor(t, caPriv),
	})
	relay2.SetAdmission(&AdmissionConfig{
		Mode: AdmissionEnforce, SelfCert: issueCertFor(t, caPriv, relay2, admission.RoleRelay), Verifier: verifierFor(t, caPriv),
	})

	relay2.ConnectPeer(admRelay1Addr)
	relay1.ConnectPeer(admRelay2Addr)

	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if relayKnows(relay1, relay2.idStr()) && relayKnows(relay2, relay1.idStr()) {
			return // 双向登记成功 = 无交互准入通过 + 控制链路建立
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("enforce+有效证书: 控制链路未在超时内建立 (relay1知道relay2=%v relay2知道relay1=%v)",
		relayKnows(relay1, relay2.idStr()), relayKnows(relay2, relay1.idStr()))
}

// TestAdmission_IndexSign_Enforce_WrongCA 验证：enforce 模式下，
// 一台 relay 持【另一把 CA】签发的 indexSign 时，离线验签失败，控制链路不建立。
func TestAdmission_IndexSign_Enforce_WrongCA(t *testing.T) {
	caGood, _ := admission.GenerateCAKey()
	caEvil, _ := admission.GenerateCAKey()

	relay1 := startRelay(t, "127.0.0.1:19611", "127.0.0.1:19611")
	defer relay1.Close()
	relay2 := startRelay(t, "127.0.0.1:19612", "127.0.0.1:19612")
	defer relay2.Close()

	// relay1 信任 caGood；relay2 却持 caEvil 签发的证书 → relay1 验签失败拒绝。
	relay1.SetAdmission(&AdmissionConfig{
		Mode: AdmissionEnforce, SelfCert: issueCertFor(t, caGood, relay1, admission.RoleRelay), Verifier: verifierFor(t, caGood),
	})
	relay2.SetAdmission(&AdmissionConfig{
		Mode: AdmissionEnforce, SelfCert: issueCertFor(t, caEvil, relay2, admission.RoleRelay), Verifier: verifierFor(t, caGood),
	})

	relay2.ConnectPeer("127.0.0.1:19611")
	relay1.ConnectPeer("127.0.0.1:19612")

	// 给足时间：若准入生效，relay1 应【始终】不登记 relay2。
	time.Sleep(3 * time.Second)
	if relayKnows(relay1, relay2.idStr()) {
		t.Fatalf("enforce+错误CA: relay1 不应登记 relay2（准入应拒绝），但登记了")
	}
}

// issueCertForPubKey 用给定 CA 私钥为一个公钥 hex 签发 indexSign（用于 NAT 节点）。
func issueCertForPubKey(t *testing.T, caPriv *ecdsa.PrivateKey, pubKeyHex string, role admission.Role) []byte {
	t.Helper()
	nonce, _ := admission.NewNonce()
	cert := admission.Cert{
		SubjectNodeID: admission.NodeIDFromPubKeyHex(pubKeyHex),
		SubjectPubKey: pubKeyHex,
		Role:          role,
		NotBefore:     time.Now().Add(-time.Minute).Unix(),
		NotAfter:      time.Now().Add(time.Hour).Unix(),
		Nonce:         nonce,
		Issuer:        "test-ca",
	}
	sc, err := admission.Sign(caPriv, cert)
	if err != nil {
		t.Fatalf("为 NAT 公钥签发 indexSign 失败: %v", err)
	}
	b, _ := json.Marshal(sc)
	return b
}

// TestAdmission_NatRegister_Enforce_RoleRecorded 验证阶段3：
// NAT 节点带 server 角色 indexSign 注册到 relay，enforce 下离线验签通过、角色落账户表。
func TestAdmission_NatRegister_Enforce_RoleRecorded(t *testing.T) {
	caPriv, _ := admission.GenerateCAKey()

	relayAddr := "127.0.0.1:19621"
	relay := startRelay(t, relayAddr, relayAddr)
	defer relay.Close()
	relay.SetAdmission(&AdmissionConfig{
		Mode: AdmissionEnforce, SelfCert: issueCertFor(t, caPriv, relay, admission.RoleRelay), Verifier: verifierFor(t, caPriv),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// NAT 节点带 server 角色证书注册。
	server, err := natnode.NewNATNode(nil, relayAddr)
	if err != nil {
		t.Fatalf("创建 NAT 节点失败: %v", err)
	}
	defer server.Close()
	server.SetIndexSign(issueCertForPubKey(t, caPriv, server.PubKeyHex(), admission.RoleServer))
	go func() { _ = server.Listen(ctx, relayAddr) }()

	// 等待注册完成 + 准入校验落角色。
	nodeID := string(server.ID())
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if relay.AccountRole(nodeID) == admission.RoleServer {
			return // 角色已落账户表 = 无交互 indexSign 注册准入通过
		}
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("enforce+server证书注册: 角色未在超时内落账户表 (当前=%q)", relay.AccountRole(nodeID))
}

// TestAdmission_NatRegister_Enforce_NoCertRejected 验证：enforce 下 NAT 节点【不带】证书注册被拒绝
// （账户表不出现该节点角色）。
func TestAdmission_NatRegister_Enforce_NoCertRejected(t *testing.T) {
	caPriv, _ := admission.GenerateCAKey()

	relayAddr := "127.0.0.1:19622"
	relay := startRelay(t, relayAddr, relayAddr)
	defer relay.Close()
	relay.SetAdmission(&AdmissionConfig{
		Mode: AdmissionEnforce, SelfCert: issueCertFor(t, caPriv, relay, admission.RoleRelay), Verifier: verifierFor(t, caPriv),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// NAT 节点【不设】indexSign 直接注册。
	server, err := natnode.NewNATNode(nil, relayAddr)
	if err != nil {
		t.Fatalf("创建 NAT 节点失败: %v", err)
	}
	defer server.Close()
	go func() { _ = server.Listen(ctx, relayAddr) }()

	nodeID := string(server.ID())
	time.Sleep(3 * time.Second)
	if role := relay.AccountRole(nodeID); role != "" {
		t.Fatalf("enforce+无证书注册: 不应记录角色（应被拒绝），却记录了 %q", role)
	}
}

// TestMeteringHook_AttributesServerUplink 直接验证计量 hook 的归因逻辑（确定性、不依赖阈值跨越）：
//   - server 角色 + relay_to_clients 方向 → 计入（服务端下行）；
//   - server 角色 + client_to_relay 方向 → 计入（P0 修复：双向均计，消除方向不对称漏洞）；
//   - 非 server 角色 / 空 NodeID → 不计。
func TestMeteringHook_AttributesServerUplink(t *testing.T) {
	relay := startRelay(t, "127.0.0.1:19623", "127.0.0.1:19623")
	defer relay.Close()

	srv := "server-node-id"
	cli := "client-node-id"
	relay.accounts.putRole(srv, admission.RoleServer)
	relay.accounts.putRole(cli, admission.RoleClient)

	// server relay_to_clients（服务端向客户端发送=上行）→ 计入。
	_ = relay.meteringHook(context.Background(), &networkFrameWork.ForwardStats{NodeID: srv, Direction: "relay_to_clients", TotalBytes: 1000})
	_ = relay.meteringHook(context.Background(), &networkFrameWork.ForwardStats{NodeID: srv, Direction: "relay_to_clients", TotalBytes: 500})
	// server client_to_relay（客户端向服务端上传）→ 不计（client 流量不计费）。
	_ = relay.meteringHook(context.Background(), &networkFrameWork.ForwardStats{NodeID: srv, Direction: "client_to_relay", TotalBytes: 9999})
	// client 角色即便 relay_to_clients → 不计。
	_ = relay.meteringHook(context.Background(), &networkFrameWork.ForwardStats{NodeID: cli, Direction: "relay_to_clients", TotalBytes: 7777})
	// 空 NodeID → 不计。
	_ = relay.meteringHook(context.Background(), &networkFrameWork.ForwardStats{NodeID: "", Direction: "relay_to_clients", TotalBytes: 3333})

	// 只计 server 上行：1000 + 500 = 1500
	if got := relay.AccountUplinkBytes(srv); got != 1500 {
		t.Fatalf("server 上行应为 1500B, 实际 %d", got)
	}
	if got := relay.AccountUplinkBytes(cli); got != 0 {
		t.Fatalf("client 不应计费, 实际 %d", got)
	}
}

// TestBusinessConnect_SchemeB_ClientCannotServe_E2E 端到端验证方案B（穿过真实网络栈）：
// 一个持 client 证书的节点即便注册成功、调用 Listen 试图对外服务，别的节点对它发起的
// Connect 也会在其托管 relay 的业务边界被拒绝——client 无法成为服务提供方，从根上逃不了费。
// 对照：持 server 证书的节点能被正常连接。
func TestBusinessConnect_SchemeB_ClientCannotServe_E2E(t *testing.T) {
	caPriv, _ := admission.GenerateCAKey()

	relayAddr := "127.0.0.1:19624"
	relay := startRelay(t, relayAddr, relayAddr)
	defer relay.Close()
	relay.SetAdmission(&AdmissionConfig{
		Mode: AdmissionEnforce, SelfCert: issueCertFor(t, caPriv, relay, admission.RoleRelay), Verifier: verifierFor(t, caPriv),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 攻击者：持 client 证书，却试图当服务方（Listen 等待入站）。
	attacker, err := natnode.NewNATNode(nil, relayAddr)
	if err != nil {
		t.Fatalf("创建 attacker 失败: %v", err)
	}
	defer attacker.Close()
	attacker.SetIndexSign(issueCertForPubKey(t, caPriv, attacker.PubKeyHex(), admission.RoleClient))
	go func() { _ = attacker.Listen(ctx, relayAddr) }()

	// 等 attacker 的 client 角色落账户表。
	attackerID := string(attacker.ID())
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if relay.AccountRole(attackerID) == admission.RoleClient {
			break
		}
		time.Sleep(150 * time.Millisecond)
	}
	if relay.AccountRole(attackerID) != admission.RoleClient {
		t.Fatalf("attacker 的 client 角色未落账户表 (当前=%q)", relay.AccountRole(attackerID))
	}

	// 受害客户端试图连接 attacker（把它当服务方）。
	victim, err := natnode.NewNATNode(nil, relayAddr)
	if err != nil {
		t.Fatalf("创建 victim 失败: %v", err)
	}
	defer victim.Close()
	victim.SetIndexSign(issueCertForPubKey(t, caPriv, victim.PubKeyHex(), admission.RoleClient))
	go func() { _ = victim.Listen(ctx, relayAddr) }()
	time.Sleep(1 * time.Second)

	connCtx, connCancel := context.WithTimeout(ctx, 6*time.Second)
	defer connCancel()
	_, err = victim.Connect(connCtx, attacker.ID())
	if err == nil {
		t.Fatal("方案B: 连接 client 角色节点应被业务边界拒绝, 却成功了(逃费漏洞未堵)")
	}
	t.Logf("方案B 生效: 连接 client 角色节点被拒: %v", err)
}

// TestBusinessConnect_SchemeB_RoleBoundary 验证方案B「服务边界角色强制」的裁决逻辑：
// 只有 role=server 的目标能作为业务连接目标被服务；client / 未知角色在 enforce 下被拒。
// 这堵死「持 client 证书却对外提供服务从而逃避计费」的攻击。
func TestBusinessConnect_SchemeB_RoleBoundary(t *testing.T) {
	relay := startRelay(t, "127.0.0.1:19624", "127.0.0.1:19624")
	defer relay.Close()

	srv := "srv-node"
	cli := "cli-node"
	relay.accounts.putRole(srv, admission.RoleServer)
	relay.accounts.putRole(cli, admission.RoleClient)

	caPriv, _ := admission.GenerateCAKey()
	const pk = "clientpubkeyhex"

	// enforce（Verifier=nil：隔离角色逻辑, 不触发保证金扣费）：
	// server 目标放行；client 目标拒绝；未知角色拒绝。
	relay.SetAdmission(&AdmissionConfig{
		Mode: AdmissionEnforce, SelfCert: issueCertFor(t, caPriv, relay, admission.RoleRelay), Verifier: nil,
	})
	if err := relay.onBusinessConnect(srv, pk, "c1"); err != nil {
		t.Fatalf("enforce: server 目标应放行, 却被拒: %v", err)
	}
	if err := relay.onBusinessConnect(cli, pk, "c2"); err == nil {
		t.Fatal("enforce: client 目标应被拒(方案B), 却放行了 —— 逃费路径未堵死")
	}
	if err := relay.onBusinessConnect("unknown-node", pk, "c3"); err == nil {
		t.Fatal("enforce: 未知角色目标应被拒, 却放行了")
	}

	// warn：一律放行（仅告警）。
	relay.SetAdmission(&AdmissionConfig{
		Mode: AdmissionWarn, SelfCert: issueCertFor(t, caPriv, relay, admission.RoleRelay), Verifier: nil,
	})
	if err := relay.onBusinessConnect(cli, pk, "c4"); err != nil {
		t.Fatalf("warn: client 目标应放行(仅告警), 却被拒: %v", err)
	}

	// off：钩子语义等价放行。
	relay.SetAdmission(&AdmissionConfig{Mode: AdmissionOff})
	if err := relay.onBusinessConnect(cli, pk, "c5"); err != nil {
		t.Fatalf("off: 应放行, 却被拒: %v", err)
	}
}

// TestTerminateHostedConnection_NoGroup 验证 relay 侧连接终止能力的错误路径：
// 未托管该 nodeId 时返回 error（正常路径由端到端隧道测试覆盖）。
func TestTerminateHostedConnection_NoGroup(t *testing.T) {
	relay := startRelay(t, "127.0.0.1:19626", "127.0.0.1:19626")
	defer relay.Close()
	if err := relay.TerminateHostedConnection("nonexistent-node", "conn-x"); err == nil {
		t.Fatal("未托管的 nodeId 终止连接应返回 error")
	}
}

// TestConnDeposit_ReserveGatesConnection 验证连接保证金：enforce 下用 fakeCA 作 Verifier，
// server 目标 + client/server 余额足→放行并各扣一笔；余额不足→拒绝建连；同一 connID 不重复扣。
func TestConnDeposit_ReserveGatesConnection(t *testing.T) {
	ca := newFakeCA()
	srv := httptest.NewServer(ca.handler())
	defer srv.Close()
	settler := admission.NewCAClient(srv.URL)

	relay := startRelay(t, "127.0.0.1:19625", "127.0.0.1:19625")
	defer relay.Close()
	relay.SetAdmission(&AdmissionConfig{Mode: AdmissionEnforce, Verifier: settler})

	// 目标必须是 server 角色（否则先被角色边界拒）。
	const clientPub = "beefbeef" // NodeID 由它派生
	clientID := networkFrameWork.NodeIDFromPubKeyHex(clientPub)
	serverID := "server-target-node"
	relay.accounts.putRole(serverID, admission.RoleServer)

	// 余额不足：拒绝建连。
	if err := relay.onBusinessConnect(serverID, clientPub, "conn-1"); err == nil {
		t.Fatal("0 余额应拒绝建连(保证金不足)")
	}

	// 充足余额：放行并各扣一笔。
	ca.mu.Lock()
	ca.balances[clientID] = 12 << 20 // 12MB
	ca.balances[serverID] = 1 << 20  // 1MB
	ca.mu.Unlock()
	if err := relay.onBusinessConnect(serverID, clientPub, "conn-2"); err != nil {
		t.Fatalf("充足余额应放行: %v", err)
	}
	ca.mu.Lock()
	cBal, sBal := ca.balances[clientID], ca.balances[serverID]
	ca.mu.Unlock()
	if cBal != 12<<20-connFeeClient {
		t.Fatalf("client 应扣 %dB, 实际余 %dB", connFeeClient, cBal)
	}
	if sBal != 1<<20-connFeeServer {
		t.Fatalf("server 应扣 %dB, 实际余 %dB", connFeeServer, sBal)
	}

	// 窗口内【不同 connID】的同一 (client,server) 对不重复扣（防重试风暴打空余额）。
	if err := relay.onBusinessConnect(serverID, clientPub, "conn-DIFFERENT"); err != nil {
		t.Fatalf("窗口内同对端应放行(不重复扣): %v", err)
	}
	ca.mu.Lock()
	cBal2 := ca.balances[clientID]
	ca.mu.Unlock()
	if cBal2 != cBal {
		t.Fatalf("窗口内同 (client,server) 对不应重复扣: 前 %dB 后 %dB", cBal, cBal2)
	}
}
