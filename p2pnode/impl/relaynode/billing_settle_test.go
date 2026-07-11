package relaynode

import (
	"bnfs_p2p/admission"
	"bnfs_p2p/networkFrameWork"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// fakeCA 是一个最小的内存计费 CA（httptest），实现 /settle 与 /credit，供 relay 结算测试。
type fakeCA struct {
	mu       sync.Mutex
	balances map[string]int64
}

func newFakeCA() *fakeCA { return &fakeCA{balances: map[string]int64{}} }

func (f *fakeCA) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(admission.PathSettle, func(w http.ResponseWriter, r *http.Request) {
		var req admission.SettleRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.balances[req.NodeID] -= req.UsedDelta
		bal := f.balances[req.NodeID]
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(admission.SettleResponse{Balance: bal, Allow: bal > 0})
	})
	mux.HandleFunc(admission.PathReserve, func(w http.ResponseWriter, r *http.Request) {
		var req admission.ReserveRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		cCur, sCur := f.balances[req.ClientNodeID], f.balances[req.ServerNodeID]
		allow := cCur >= req.ClientFee && sCur >= req.ServerFee
		if allow {
			f.balances[req.ClientNodeID] = cCur - req.ClientFee
			f.balances[req.ServerNodeID] = sCur - req.ServerFee
			cCur, sCur = f.balances[req.ClientNodeID], f.balances[req.ServerNodeID]
		}
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(admission.ReserveResponse{Allow: allow, ClientBalance: cCur, ServerBalance: sCur})
	})
	mux.HandleFunc(admission.PathCredit, func(w http.ResponseWriter, r *http.Request) {
		var req admission.CreditRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		f.mu.Lock()
		f.balances[req.NodeID] += req.AddBytes
		bal := f.balances[req.NodeID]
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(admission.CreditResponse{Balance: bal})
	})
	return mux
}

// TestSettlement_ExhaustTriggersCutoff 验证结算闭环：
// 充足余额→结算放行不熔断；余额耗尽→结算裁决 Allow=false→节点被 cutoff→metering hook 返回 error。
func TestSettlement_ExhaustTriggersCutoff(t *testing.T) {
	ca := newFakeCA()
	srv := httptest.NewServer(ca.handler())
	defer srv.Close()

	settler := admission.NewCAClient(srv.URL)

	relay := startRelay(t, "127.0.0.1:19631", "127.0.0.1:19631")
	defer relay.Close()
	relay.SetAdmission(&AdmissionConfig{Mode: AdmissionEnforce, Verifier: settler})

	srvNode := "server-node-1"
	relay.accounts.putRole(srvNode, admission.RoleServer)
	// 注册即可服务（无默认熔断）；直接测试结算驱动的熔断逻辑。

	// 场景1：CA 有充足余额 → 结算后放行、hook 不熔断。
	ca.mu.Lock()
	ca.balances[srvNode] = 10000
	ca.mu.Unlock()
	relay.accounts.addUplink(srvNode, 3000) // 模拟已计量 3000B
	relay.settleOnce(settler)               // 上报增量 3000，余额 10000-3000=7000>0
	if relay.accounts.isCutoff(srvNode) {
		t.Fatalf("余额充足时不应熔断")
	}
	if err := relay.meteringHook(context.Background(), &networkFrameWork.ForwardStats{
		NodeID: srvNode, Direction: "relay_to_clients", TotalBytes: 100,
	}); err != nil {
		t.Fatalf("余额充足时 hook 不应返回 error: %v", err)
	}

	// 场景2：继续用量把余额打到 <=0 → 结算裁决熔断 → hook 返回 error。
	relay.accounts.addUplink(srvNode, 8000) // 再计量 8000B（累计上报增量将是 8000）
	relay.settleOnce(settler)               // 余额 7000-8000=-1000<=0 → Allow=false
	if !relay.accounts.isCutoff(srvNode) {
		t.Fatalf("余额耗尽后应被熔断")
	}
	if err := relay.meteringHook(context.Background(), &networkFrameWork.ForwardStats{
		NodeID: srvNode, Direction: "relay_to_clients", TotalBytes: 100,
	}); err == nil {
		t.Fatalf("熔断后 metering hook 应返回 error 以停止转发")
	}
}

// TestMetering_OnlyServerUplinkCharged 验证既定模型：只计 server 上行(relay_to_clients)，
// client 上传方向(client_to_relay)【不计费】——client 流量不计量，一切由 server 上行扣费。
func TestMetering_OnlyServerUplinkCharged(t *testing.T) {
	relay := startRelay(t, "127.0.0.1:19632", "127.0.0.1:19632")
	defer relay.Close()
	relay.SetAdmission(&AdmissionConfig{Mode: AdmissionEnforce})

	srvNode := "server-node-dir"
	relay.accounts.putRole(srvNode, admission.RoleServer)

	before := relay.AccountUplinkBytes(srvNode)
	// server 上行：计。
	_ = relay.meteringHook(context.Background(), &networkFrameWork.ForwardStats{
		NodeID: srvNode, Direction: "relay_to_clients", TotalBytes: 1000,
	})
	// client 上传：不计。
	_ = relay.meteringHook(context.Background(), &networkFrameWork.ForwardStats{
		NodeID: srvNode, Direction: "client_to_relay", TotalBytes: 2000,
	})
	if got := relay.AccountUplinkBytes(srvNode) - before; got != 1000 {
		t.Fatalf("只应计 server 上行 1000B, 实际 %dB", got)
	}
}

// TestSettle_CutoffOnBalanceExhaust 验证：结算发现 server 上行余额耗尽 → cutoff → hook 熔断上行。
func TestSettle_CutoffOnBalanceExhaust(t *testing.T) {
	ca := newFakeCA()
	srv := httptest.NewServer(ca.handler())
	defer srv.Close()
	settler := admission.NewCAClient(srv.URL)

	relay := startRelay(t, "127.0.0.1:19633", "127.0.0.1:19633")
	defer relay.Close()
	relay.SetAdmission(&AdmissionConfig{Mode: AdmissionEnforce, Verifier: settler})

	srvNode := "server-node-exhaust"
	relay.accounts.putRole(srvNode, admission.RoleServer)
	ca.mu.Lock()
	ca.balances[srvNode] = 1000
	ca.mu.Unlock()

	// 计量 1500B 上行 → 结算后余额 1000-1500<0 → cutoff。
	_ = relay.meteringHook(context.Background(), &networkFrameWork.ForwardStats{
		NodeID: srvNode, Direction: "relay_to_clients", TotalBytes: 1500,
	})
	relay.settleOnce(settler)
	if !relay.accounts.isCutoff(srvNode) {
		t.Fatal("server 上行余额耗尽后应被熔断")
	}
	if err := relay.meteringHook(context.Background(), &networkFrameWork.ForwardStats{
		NodeID: srvNode, Direction: "relay_to_clients", TotalBytes: 100,
	}); err == nil {
		t.Fatal("熔断后 server 上行应被 hook 拒绝")
	}
}

// TestSettle_RecoverAfterRecredit 验证熔断后充值可恢复：余额耗尽→cutoff→充值→探针解除熔断。
func TestSettle_RecoverAfterRecredit(t *testing.T) {
	ca := newFakeCA()
	srv := httptest.NewServer(ca.handler())
	defer srv.Close()
	settler := admission.NewCAClient(srv.URL)

	relay := startRelay(t, "127.0.0.1:19636", "127.0.0.1:19636")
	defer relay.Close()
	relay.SetAdmission(&AdmissionConfig{Mode: AdmissionEnforce, Verifier: settler})

	srvNode := "server-node-recover"
	relay.accounts.putRole(srvNode, admission.RoleServer)
	ca.mu.Lock()
	ca.balances[srvNode] = 500
	ca.mu.Unlock()

	// 计量 1000B → 结算余额<0 → cutoff。
	_ = relay.meteringHook(context.Background(), &networkFrameWork.ForwardStats{NodeID: srvNode, Direction: "relay_to_clients", TotalBytes: 1000})
	relay.settleOnce(settler)
	if !relay.accounts.isCutoff(srvNode) {
		t.Fatal("余额耗尽应熔断")
	}

	// 管理员充值 → 下一轮探针应解除熔断（关键：熔断后无新增 delta，靠探针恢复）。
	ca.mu.Lock()
	ca.balances[srvNode] = 1_000_000
	ca.mu.Unlock()
	relay.settleOnce(settler)
	if relay.accounts.isCutoff(srvNode) {
		t.Fatal("充值后探针应解除熔断")
	}
}

// TestRegister_NoDefaultCutoff 验证既定模型：注册即可服务（不默认熔断），
// 白嫖由建连保证金兜底，而非注册期默认熔断（那会给合法 server 引入启动延迟）。
func TestRegister_NoDefaultCutoff(t *testing.T) {
	relay := startRelay(t, "127.0.0.1:19634", "127.0.0.1:19634")
	defer relay.Close()
	relay.SetAdmission(&AdmissionConfig{Mode: AdmissionEnforce})

	srvNode := "server-node-new"
	relay.accounts.putRole(srvNode, admission.RoleServer)
	if relay.accounts.isCutoff(srvNode) {
		t.Fatal("注册即应可服务, 不默认熔断(白嫖由建连保证金兜底)")
	}
	if err := relay.meteringHook(context.Background(), &networkFrameWork.ForwardStats{
		NodeID: srvNode, Direction: "relay_to_clients", TotalBytes: 100,
	}); err != nil {
		t.Fatalf("注册后 server 上行不应被拒: %v", err)
	}
}
