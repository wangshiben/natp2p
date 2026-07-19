package relaynode

// 本文件是对外部 CA 服务的可选活体回归测试：
// 仅当环境变量 BNFS_LIVE_CA 指向测试端点（可经延迟代理）时运行，否则跳过。
//
// 它把攻击落在计费判定真正发生的地方——relay 的 onBusinessConnect 门 + 测试 CA /reserve：
//   - 用 admission.CAClient 指向测试 CA（可通过延迟代理模拟跨节点往返）；
//   - 两个全新 0 余额身份(server B / client A), 只在本地 putRole 落 server 角色
//     (= 免费 /issue server 证注册的忠实等价, 见 admission_register.go onRegisterVerify)；
//   - 并发发起同 (A,B) 对的 onBusinessConnect —— 复刻 dual-leg / 并发 Connect 的天然并发；
//   - 断言: 测试 CA 全程【0 次成功扣费】(0 余额, reserve 必拒)，且所有并发连接都被拒绝。
//
// onBusinessConnect 返回 nil 即意味着该业务连接可被接上 server B；因此 0 余额时任何一次
// 放行都代表 TOCTOU 回归。
//
// 运行:
//   BNFS_LIVE_CA=http://127.0.0.1:9001 go test ./p2pnode/impl/relaynode/ \
//       -run TestLiveDeposit_TOCTOU_AgainstDeployedCA -v -count=1

import (
	"bnfs_p2p/admission"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func liveBalance(caURL, nodeID string) int64 {
	resp, err := http.Get(caURL + "/balance?node=" + nodeID)
	if err != nil {
		return -1
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var m map[string]int64
	if json.Unmarshal(body, &m) != nil {
		return -1
	}
	return m["balance"]
}

func TestLiveDeposit_TOCTOU_AgainstDeployedCA(t *testing.T) {
	caURL := os.Getenv("BNFS_LIVE_CA")
	if caURL == "" {
		t.Skip("设置 BNFS_LIVE_CA=http://127.0.0.1:9001（可选延迟代理测试端点）才运行活体演示")
	}

	// CA 客户端从测试端点拉取公钥，/reserve 可经延迟代理。
	settler := admission.NewCAClient(caURL)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := settler.RefreshPubKey(ctx); err != nil {
		t.Fatalf("无法从测试 CA 拉取公钥: %v", err)
	}

	relay := startRelay(t, "127.0.0.1:19670", "127.0.0.1:19670")
	defer relay.Close()
	relay.SetAdmission(&AdmissionConfig{Mode: AdmissionEnforce, Verifier: settler})

	// 两个全新 0 余额身份。serverID 使用合成标识，clientNodeID 仍按 CA 口径派生:
	// onBusinessConnect 用 networkFrameWork.NodeIDFromPubKeyHex(clientPubKeyHex) 派生 client 身份。
	// 这里 clientPub 取任意新 hex, 保证 CA 账本里余额=0(从未 /credit)。
	clientPub := fmt.Sprintf("deadbeef%d", time.Now().UnixNano())
	serverID := fmt.Sprintf("live-server-target-%d", time.Now().UnixNano())
	relay.accounts.putRole(serverID, admission.RoleServer) // = B 用免费 server 证注册的忠实等价

	// 攻击前: 确认测试 CA 账本里两者余额均为 0。
	// (clientNodeID 由 relay 侧同一函数派生, 这里只需确认 server 侧; client 侧新 hex 必为 0。)
	t.Logf("攻击前 server 余额(测试 CA)=%dB", liveBalance(caURL, serverID))

	// 并发发起同 (A,B) 对的 onBusinessConnect, 各自不同 connID —— 复刻 dual-leg/并发 Connect。
	const concurrency = 24
	var freePass, rejected int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // 尽量同时冲, 制造占位窗口重叠
			connID := fmt.Sprintf("live-conn-%d", i)
			if err := relay.onBusinessConnect(serverID, clientPub, connID); err == nil {
				atomic.AddInt64(&freePass, 1)
			} else {
				atomic.AddInt64(&rejected, 1)
			}
		}(i)
	}
	close(start)
	wg.Wait()

	// 测试 CA 账本: 全程应无任何成功扣费(0 余额 → reserve 必拒)。
	cBalAfter := liveBalance(caURL, serverID)
	fp := atomic.LoadInt64(&freePass)
	rj := atomic.LoadInt64(&rejected)
	t.Logf("并发 %d 条 onBusinessConnect(测试 CA /reserve): 免费放行=%d 拒绝=%d; 攻击后 server 余额=%dB",
		concurrency, fp, rj, cBalAfter)

	if cBalAfter < 0 {
		t.Fatalf("CA 余额查询失败, CA 未正常部署?")
	}
	if fp > 0 {
		t.Fatalf("测试 CA 未成功扣费时不应放行连接，实际免费放行=%d", fp)
	}
	if rj != concurrency {
		t.Fatalf("应拒绝全部 %d 条连接，实际拒绝=%d", concurrency, rj)
	}
}
