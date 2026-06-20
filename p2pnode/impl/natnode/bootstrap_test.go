package natnode

import (
	"strings"
	"testing"

	"bnfs_p2p/p2pnode"
	"bnfs_p2p/p2pnode/relayquery"
)

// 构造可控 XOR 距离的 NodeID: self 全 0, 则任意 relay 到 self 的 XOR 距离 = 该 relay 的数值,
// 于是 hex 值越小越「近」。
func hexID(prefix string) string {
	if len(prefix) > 64 {
		prefix = prefix[:64]
	}
	return prefix + strings.Repeat("0", 64-len(prefix))
}

func TestSelectEntryRelay(t *testing.T) {
	self := p2pnode.NodeID(strings.Repeat("0", 64))
	const indexAddr = "38.76.170.102:9000"

	near := relayquery.Info{NodeID: hexID("1"), Addr: "104.252.30.204:9000"} // 距离小
	far := relayquery.Info{NodeID: hexID("f"), Addr: "203.0.113.9:9000"}     // 距离大
	indexSelf := relayquery.Info{NodeID: hexID("a"), Addr: indexAddr}         // index 自身条目

	allReachable := func(string) bool { return true }
	noneReachable := func(string) bool { return false }
	only := func(addrs ...string) func(string) bool {
		set := map[string]bool{}
		for _, a := range addrs {
			set[a] = true
		}
		return func(a string) bool { return set[a] }
	}

	t.Run("最近可达者优先", func(t *testing.T) {
		got, viaSub := selectEntryRelay(self, indexAddr, []relayquery.Info{indexSelf, far, near}, allReachable)
		if got != near.Addr || !viaSub {
			t.Fatalf("期望选中最近子 relay %s(viaSub=true), 实际 %s(viaSub=%v)", near.Addr, got, viaSub)
		}
	})

	t.Run("最近不可达则切次近", func(t *testing.T) {
		// near 不可达, far 可达 → 应回退到「第二近」的 far。
		got, viaSub := selectEntryRelay(self, indexAddr, []relayquery.Info{near, far}, only(far.Addr))
		if got != far.Addr || !viaSub {
			t.Fatalf("期望切到次近 relay %s(viaSub=true), 实际 %s(viaSub=%v)", far.Addr, got, viaSub)
		}
	})

	t.Run("子relay全不可达则回退index", func(t *testing.T) {
		got, viaSub := selectEntryRelay(self, indexAddr, []relayquery.Info{near, far}, noneReachable)
		if got != indexAddr || viaSub {
			t.Fatalf("期望回退 index %s(viaSub=false), 实际 %s(viaSub=%v)", indexAddr, got, viaSub)
		}
	})

	t.Run("无子relay只有index自身则回退index", func(t *testing.T) {
		// 列表里只有 index 自身（addr==indexAddr）, 应被排除出候选, 直接回退 index。
		got, viaSub := selectEntryRelay(self, indexAddr, []relayquery.Info{indexSelf}, allReachable)
		if got != indexAddr || viaSub {
			t.Fatalf("期望回退 index %s(viaSub=false), 实际 %s(viaSub=%v)", indexAddr, got, viaSub)
		}
	})

	t.Run("index自身条目即使可达也不作为子relay候选", func(t *testing.T) {
		// indexSelf 距离(0xa...) 比 near(0x1...) 远, 但即便它更近也不该被当子 relay 选走。
		got, viaSub := selectEntryRelay(self, indexAddr, []relayquery.Info{indexSelf, near}, allReachable)
		if got != near.Addr || !viaSub {
			t.Fatalf("期望选中子 relay %s, 实际 %s(viaSub=%v)", near.Addr, got, viaSub)
		}
	})

	t.Run("空列表回退index", func(t *testing.T) {
		got, viaSub := selectEntryRelay(self, indexAddr, nil, allReachable)
		if got != indexAddr || viaSub {
			t.Fatalf("期望回退 index, 实际 %s(viaSub=%v)", got, viaSub)
		}
	})
}
