package natnode

import (
	"bnfs_p2p/p2pnode"
	"bnfs_p2p/p2pnode/relayquery"
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"
)

func selectorInfo(value int, address string, onlineSince, lastSeen time.Time) relayquery.Info {
	return relayquery.Info{
		NodeID:                fmt.Sprintf("%064x", value),
		Addr:                  address,
		ContinuousOnlineSince: onlineSince.Unix(),
		LastControlSeen:       lastSeen.Unix(),
	}
}

func selectorWithRTT(now time.Time, values map[string]time.Duration) relaySelector {
	selector := newRelaySelector()
	selector.now = func() time.Time { return now }
	selector.probe = func(_ context.Context, info relayquery.Info) (time.Duration, error) {
		rtt, ok := values[info.Addr]
		if !ok {
			return 0, errors.New("unreachable")
		}
		return rtt, nil
	}
	return selector
}

func TestRelaySelectorRTTBandThenStableAge(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	indexAddr := "192.0.2.1:9000"
	a := selectorInfo(1, "192.0.2.10:9000", now.Add(-72*time.Hour), now)
	b := selectorInfo(100, "192.0.2.11:9000", now.Add(-24*time.Hour), now)
	c := selectorInfo(200, "192.0.2.12:9000", now.Add(-240*time.Hour), now)
	selector := selectorWithRTT(now, map[string]time.Duration{
		a.Addr: 180 * time.Millisecond,
		b.Addr: 35 * time.Millisecond,
		c.Addr: 38 * time.Millisecond,
	})
	selection := selector.Select(context.Background(), p2pnode.NodeID(fmt.Sprintf("%064x", 0)), indexAddr, []relayquery.Info{a, b, c})
	if selection.Address != c.Addr {
		t.Fatalf("B/C 同 RTT 档时应选择稳定更久的 C，实际 %+v", selection)
	}
	if selection.RTTBand != 0 || selection.StableAge != 240*time.Hour {
		t.Fatalf("选择解释不正确: %+v", selection)
	}
}

func TestRelaySelectorPhysicalRTTOverridesCloserXORDistance(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	selfID := p2pnode.NodeID(fmt.Sprintf("%064x", 0))
	serverN := selectorInfo(1, "192.0.2.10:9000", now.Add(-240*time.Hour), now)
	serverX := relayquery.Info{
		NodeID:                "8000000000000000000000000000000000000000000000000000000000000000",
		Addr:                  "192.0.2.11:9000",
		ContinuousOnlineSince: now.Add(-time.Hour).Unix(),
		LastControlSeen:       now.Unix(),
	}
	if selfID.XOR(p2pnode.NodeID(serverN.NodeID)).Cmp(selfID.XOR(p2pnode.NodeID(serverX.NodeID))) >= 0 {
		t.Fatal("测试前提不成立：serverN 必须在 XOR 逻辑距离上更近")
	}
	selector := selectorWithRTT(now, map[string]time.Duration{
		serverN.Addr: 65 * time.Millisecond,
		serverX.Addr: 45 * time.Millisecond,
	})

	selection := selector.Select(context.Background(), selfID, "192.0.2.1:9000", []relayquery.Info{serverN, serverX})
	if selection.Address != serverX.Addr || selection.RTTBand != 0 {
		t.Fatalf("serverN 逻辑更近且更稳定时，跨 RTT 档仍应选择物理更近的 serverX，实际 %+v", selection)
	}
}

func TestRelaySelectorBandPrecedesStableAgeAndFallsBack(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	indexAddr := "192.0.2.1:9000"
	fast := selectorInfo(10, "192.0.2.10:9000", now.Add(-time.Hour), now)
	slowStable := selectorInfo(11, "192.0.2.11:9000", now.Add(-240*time.Hour), now)
	selector := selectorWithRTT(now, map[string]time.Duration{
		fast.Addr:       30 * time.Millisecond,
		slowStable.Addr: 50 * time.Millisecond,
	})
	selection := selector.Select(context.Background(), p2pnode.NodeID(fmt.Sprintf("%064x", 0)), indexAddr, []relayquery.Info{slowStable, fast})
	if selection.Address != fast.Addr {
		t.Fatalf("稳定时间不能跨 RTT 档反转结果，实际 %+v", selection)
	}

	selector.probe = func(context.Context, relayquery.Info) (time.Duration, error) {
		return 0, errors.New("unreachable")
	}
	fallback := selector.Select(context.Background(), p2pnode.NodeID(fmt.Sprintf("%064x", 0)), indexAddr, []relayquery.Info{fast})
	if !fallback.Fallback || fallback.Address != indexAddr {
		t.Fatalf("全部不可达时应回退 Index，实际 %+v", fallback)
	}
}

func TestRelaySelectorIndexParticipationIsOptIn(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	indexAddr := "192.0.2.1:9000"
	index := selectorInfo(1, indexAddr, now.Add(-48*time.Hour), now)
	subRelay := selectorInfo(2, "192.0.2.2:9000", now.Add(-time.Hour), now)
	selector := selectorWithRTT(now, map[string]time.Duration{
		index.Addr:    5 * time.Millisecond,
		subRelay.Addr: 30 * time.Millisecond,
	})

	selection := selector.Select(context.Background(), p2pnode.NodeID(fmt.Sprintf("%064x", 0)), indexAddr, []relayquery.Info{index, subRelay})
	if selection.Address != subRelay.Addr || selection.SelectedIndex || selection.Fallback {
		t.Fatalf("默认应排除 Index，仅选择子 Relay，实际 %+v", selection)
	}

	selector.includeIndex = true
	selection = selector.Select(context.Background(), p2pnode.NodeID(fmt.Sprintf("%064x", 0)), indexAddr, []relayquery.Info{index, subRelay})
	if selection.Address != indexAddr || !selection.SelectedIndex || selection.Fallback || selection.Eligible != 2 {
		t.Fatalf("显式启用后应由低 RTT Index 正常胜出，实际 %+v", selection)
	}
}

func TestRelaySelectorIncludingIndexStillFallsBackWhenAllUnreachable(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	indexAddr := "192.0.2.1:9000"
	selector := selectorWithRTT(now, nil)
	selector.includeIndex = true
	selection := selector.Select(context.Background(), p2pnode.NodeID(fmt.Sprintf("%064x", 0)), indexAddr, []relayquery.Info{
		selectorInfo(1, indexAddr, now.Add(-time.Hour), now),
		selectorInfo(2, "192.0.2.2:9000", now.Add(-time.Hour), now),
	})
	if selection.Address != indexAddr || !selection.Fallback || selection.SelectedIndex {
		t.Fatalf("所有质量候选不可达时仍应标记为 Index fallback，实际 %+v", selection)
	}
}

func TestRelaySelectorFiltersStaleInvalidAndDuplicateCandidates(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	indexAddr := "192.0.2.1:9000"
	valid := selectorInfo(10, "192.0.2.10:9000", now.Add(-time.Hour), now)
	duplicateOld := valid
	duplicateOld.NodeID = fmt.Sprintf("%064x", 11)
	duplicateOld.LastControlSeen = now.Add(-time.Minute).Unix()
	stale := selectorInfo(12, "192.0.2.12:9000", now.Add(-time.Hour), now.Add(-3*time.Minute))
	invalid := relayquery.Info{NodeID: "not-hex", Addr: "192.0.2.13:9000"}
	selector := selectorWithRTT(now, map[string]time.Duration{
		valid.Addr: 20 * time.Millisecond,
		stale.Addr: 10 * time.Millisecond,
	})
	selection := selector.Select(context.Background(), p2pnode.NodeID(fmt.Sprintf("%064x", 0)), indexAddr,
		[]relayquery.Info{invalid, stale, duplicateOld, valid})
	if selection.Address != valid.Addr || selection.Eligible != 1 {
		t.Fatalf("过滤结果不正确: %+v", selection)
	}
}

func TestRelaySelectorLegacyMetadataAndDeterministicTieBreak(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	indexAddr := "192.0.2.1:9000"
	near := relayquery.Info{NodeID: fmt.Sprintf("%064x", 1), Addr: "192.0.2.10:9000"}
	far := relayquery.Info{NodeID: fmt.Sprintf("%064x", 2), Addr: "192.0.2.11:9000"}
	selector := selectorWithRTT(now, map[string]time.Duration{
		near.Addr: 20 * time.Millisecond,
		far.Addr:  20 * time.Millisecond,
	})
	selfID := p2pnode.NodeID(fmt.Sprintf("%064x", 0))
	first := selector.Select(context.Background(), selfID, indexAddr, []relayquery.Info{far, near})
	second := selector.Select(context.Background(), selfID, indexAddr, []relayquery.Info{near, far})
	if first.Address != near.Addr || second.Address != near.Addr {
		t.Fatalf("缺少新字段时应兼容，并由 XOR 确定性决胜: first=%+v second=%+v", first, second)
	}
}

func TestRelaySelectorProbeConcurrencyBound(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	selector := newRelaySelector()
	selector.now = func() time.Time { return now }
	selector.concurrency = 3
	var active atomic.Int32
	var maximum atomic.Int32
	selector.probe = func(ctx context.Context, _ relayquery.Info) (time.Duration, error) {
		current := active.Add(1)
		for {
			observed := maximum.Load()
			if current <= observed || maximum.CompareAndSwap(observed, current) {
				break
			}
		}
		defer active.Add(-1)
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(5 * time.Millisecond):
			return 20 * time.Millisecond, nil
		}
	}
	infos := make([]relayquery.Info, 12)
	for index := range infos {
		infos[index] = selectorInfo(index+1, fmt.Sprintf("192.0.2.%d:9000", index+10), now.Add(-time.Hour), now)
	}
	selection := selector.Select(context.Background(), p2pnode.NodeID(fmt.Sprintf("%064x", 0)), "192.0.2.1:9000", infos)
	if selection.Fallback || selection.Eligible != len(infos) {
		t.Fatalf("并发探测选择失败: %+v", selection)
	}
	if got := maximum.Load(); got > 3 {
		t.Fatalf("探测并发超过上限: %d", got)
	}
}
