package relaynode

import (
	"bnfs_p2p/admission"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// slowDenyCA 是已退役 /reserve 的绊线服务：只要业务角色门误调用该端点就记录命中，
// 并在短暂延迟后拒绝，以放大并发回归的可见性。
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

// TestBusinessConnectNeverCallsRetiredReserve verifies that concurrent business
// legs cannot re-enter the retired unilateral charging endpoint. Admission now
// enforces the target role here; byte authorization happens in the mutually
// signed record gate before any application frame is released.
func TestBusinessConnectNeverCallsRetiredReserve(t *testing.T) {
	ca := &slowDenyCA{hold: 150 * time.Millisecond}
	srv := httptest.NewServer(ca.handler())
	defer srv.Close()
	settler := admission.NewCAClient(srv.URL)

	relay := startRelay(t, "127.0.0.1:19648", "127.0.0.1:19648")
	defer relay.Close()
	relay.mu.Lock()
	relay.admission = &AdmissionConfig{Mode: AdmissionEnforce, Verifier: settler}
	relay.mu.Unlock()

	// 目标是 server 角色；Verifier 指向绊线服务，确保任何旧端点回归都可观测。
	const clientPub = "deadbeefcafe"
	serverID := "toctou-server-target"
	relay.accounts.putRole(serverID, admission.RoleServer)

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
			// 轻微错峰，覆盖并发和连续进入业务角色门的情况。
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

	t.Logf("并发角色门 %d 条: 放行=%d 拒绝=%d; 已停用 /reserve 命中=%d 次; CA 放行=%d 次",
		N, allowed, denied, atomic.LoadInt64(&ca.reserveHits), atomic.LoadInt64(&ca.allowed))

	if atomic.LoadInt64(&ca.allowed) != 0 {
		t.Fatalf("测试前提被破坏: CA 本应从不放行, 却放行了 %d 次", ca.allowed)
	}
	if allowed != N || denied != 0 {
		t.Fatalf("server 角色门应放行全部 %d 条并交给双签数据门，放行=%d 拒绝=%d", N, allowed, denied)
	}
	if hits := atomic.LoadInt64(&ca.reserveHits); hits != 0 {
		t.Fatalf("业务角色门不得调用已停用 /reserve，实际命中=%d", hits)
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
