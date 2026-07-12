package relaynode

import (
	"bnfs_p2p/admission"
	"bnfs_p2p/networkFrameWork"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// slowDenyCA 是一个【慢速拒绝】的假 CA：/reserve 先阻塞 hold 时长(模拟真实 CA 往返 + ledger
// 全局锁串行化 + fsync 落盘的耗时窗口)，然后【永远】返回 Allow=false（0 余额，任何扣费都失败）。
// 它精确复刻真实攻击条件：攻击者两个 0 余额身份，CA 从不放行扣费。
//
// 若在这种"CA 从不成功扣费"的前提下，仍有 onBusinessConnect 返回 nil（放行建连），
// 那就证明放行不是因为扣费成功，而是命中了去重 free-pass 分支 —— 即 TOCTOU 漏洞。
type slowDenyCA struct {
	hold        time.Duration
	reserveHits int64 // 收到多少次 /reserve（全部会被拒）
	allowed     int64 // CA 真正放行(扣费成功)的次数——本 CA 恒为 0
}

func (f *slowDenyCA) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(admission.PathReserve, func(w http.ResponseWriter, r *http.Request) {
		var req admission.ReserveRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		atomic.AddInt64(&f.reserveHits, 1)
		// 持占位窗口：真实里这是 loopback HTTP + ledger 全局锁 + rename fsync 的耗时。
		time.Sleep(f.hold)
		// 0 余额：永远拒绝，绝不扣费成功。
		_ = json.NewEncoder(w).Encode(admission.ReserveResponse{Allow: false, ClientBalance: 0, ServerBalance: 0})
	})
	return mux
}

// TestConnDeposit_TOCTOU_FreePass 回归验证并发同 (client,server) 对不会把 pending /reserve
// 误当成已付款。CA 永远拒绝时，所有连接都必须被拒，且只应有 leader 发起一次预扣。
func TestConnDeposit_TOCTOU_FreePass(t *testing.T) {
	ca := &slowDenyCA{hold: 150 * time.Millisecond}
	srv := httptest.NewServer(ca.handler())
	defer srv.Close()
	settler := admission.NewCAClient(srv.URL)

	relay := startRelay(t, "127.0.0.1:19648", "127.0.0.1:19648")
	defer relay.Close()
	relay.SetAdmission(&AdmissionConfig{Mode: AdmissionEnforce, Verifier: settler})

	// 目标是 server 角色(过角色边界)；client/server 余额均为 0(攻击者两个免费领证身份)。
	const clientPub = "deadbeefcafe"
	clientID := networkFrameWork.NodeIDFromPubKeyHex(clientPub)
	serverID := "toctou-server-target"
	relay.accounts.putRole(serverID, admission.RoleServer)
	_ = clientID

	// 并发发起 N 个同 (client,server) 对、不同 connID 的业务连接。
	// 这精确模拟：攻击者对同一对端并发/连续发起多条 Connect（本 codebase 的 dual-leg 与
	// 客户端重试天然制造这种并发），每条落进传输层 onBusinessConnect。
	const N = 32
	var allowed, denied int64
	var wg sync.WaitGroup
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// 轻微错峰，使部分调用落进先行者的 /reserve 持占位窗口(0~hold 之间)。
			time.Sleep(time.Duration(i) * 3 * time.Millisecond)
			connID := "toctou-conn-" + itoa(i)
			if err := relay.onBusinessConnect(serverID, clientPub, connID); err == nil {
				atomic.AddInt64(&allowed, 1)
			} else {
				atomic.AddInt64(&denied, 1)
			}
		}(i)
	}
	wg.Wait()

	t.Logf("并发建连 %d 条: 放行=%d 拒绝=%d; CA /reserve 命中=%d 次, CA 成功扣费=%d 次",
		N, allowed, denied, atomic.LoadInt64(&ca.reserveHits), atomic.LoadInt64(&ca.allowed))

	if atomic.LoadInt64(&ca.allowed) != 0 {
		t.Fatalf("测试前提被破坏: CA 本应从不放行, 却放行了 %d 次", ca.allowed)
	}
	if allowed > 0 {
		t.Fatalf("0 余额 + CA 从不扣费时不应有免费放行，实际放行=%d", allowed)
	}
	if denied != N {
		t.Fatalf("应拒绝全部 %d 条连接，实际拒绝=%d", N, denied)
	}
	if hits := atomic.LoadInt64(&ca.reserveHits); hits != 1 {
		t.Fatalf("同一 pending 裁决应只请求 CA 一次，实际 /reserve=%d", hits)
	}
}

// itoa 是极小的 int→string，避免额外 import。
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [12]byte
	p := len(b)
	for i > 0 {
		p--
		b[p] = byte('0' + i%10)
		i /= 10
	}
	return string(b[p:])
}
