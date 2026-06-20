package natnode

import (
	"bnfs_p2p/networkFrameWork"
	"bnfs_p2p/networkFrameWork/client"
	"bnfs_p2p/p2pnode"
	"bnfs_p2p/p2pnode/relayquery"

	"context"
	"fmt"
	"log"
	"math/big"
	"net"
	"sort"
	"time"
)

const (
	// relayQueryTimeout 是向 index 拉取 relay 列表的整体超时。
	relayQueryTimeout = 5 * time.Second
	// relayProbeTimeout 是探测某个 relay 是否可达（TCP 连得上）的单次超时。
	relayProbeTimeout = 3 * time.Second
)

// Bootstrap 让 NAT 节点在上线前先向 index 询问已知 relay, 按「就近优先 + 不可达回退」选定入口 relay。
//
// 流程（对应需求 2）:
//  1. 向 indexAddr 发一次性查询, 取回 index 已知的 relay 列表（含 index 自身作为兜底）。
//  2. 在「子 relay」（即非 index 自身的 relay）里按 XOR 距离升序逐个探测可达性,
//     首个连得上的即入口 relay —— 这实现「最近不可达则切次近」。
//  3. 若没有可达的子 relay（或 index 没有任何子 relay）, 回退到 index 自身作为入口
//     （即把本节点直接注册为 index 的 NAT 节点）。
//  4. 把选定的入口 relay 设为本节点唯一入口（entryRelays）, 返回其地址。
//
// 返回选定的入口 relay 地址; 调用方随后用它 Listen(ctx, entry) 完成真正的注册。
// 查询失败时不报错, 直接回退 index（保证总能上线）。
func (n *NATNode) Bootstrap(ctx context.Context, indexAddr string) (string, error) {
	relays, err := n.queryIndexRelays(ctx, indexAddr)
	if err != nil {
		log.Printf("[natnode] 向 index %s 查询 relay 列表失败, 回退直接注册到 index: %v", indexAddr, err)
		n.setSoleEntryRelay(indexAddr)
		return indexAddr, nil
	}
	log.Printf("[natnode] index %s 返回 %d 个 relay", indexAddr, len(relays))

	entry, viaSubRelay := selectEntryRelay(n.ID(), indexAddr, relays, probeRelayReachable)
	if viaSubRelay {
		log.Printf("[natnode] 选定就近可达的子 relay 作为入口: %s", entry)
	} else {
		log.Printf("[natnode] 无可达子 relay, 回退注册到 index: %s", entry)
	}
	n.setSoleEntryRelay(entry)
	return entry, nil
}

// queryIndexRelays 向 index 发起一次性 RelayQueryRoute 查询, 取回其已知 relay 列表。
func (n *NATNode) queryIndexRelays(ctx context.Context, indexAddr string) ([]relayquery.Info, error) {
	// 用 TCP 单 leg 控制流拨号（带 RouteName）: index 的 MissingGroupHandler 据 RouteName 识别为查询请求。
	// 必须用 TCP-only(而非 dual): dual 的 KCP+TCP 两条 leg 会把同一首帧重复投递, 在跨中继桥接路径上
	// 让对端把公钥帧收两次导致端到端 TLS 握手错位。targetNodeId 用本节点 ID 占位即可(index 不托管它)。
	stream, _, err := networkFrameWork.TryConnectControlStreamTCP(
		indexAddr, string(n.ID()), n.identity.Pubkey(), relayquery.Route)
	if err != nil {
		return nil, fmt.Errorf("拨号 index %s 失败: %w", indexAddr, err)
	}
	sc := client.NewStreamClient(stream)
	defer sc.Close()

	qctx, cancel := context.WithTimeout(ctx, relayQueryTimeout)
	defer cancel()

	msg, err := sc.NextMessage(qctx)
	if err != nil {
		return nil, fmt.Errorf("读取 relay 列表应答失败: %w", err)
	}
	resp, err := relayquery.DecodeListResp(msg)
	if err != nil {
		return nil, err
	}
	return resp.Relays, nil
}

// setSoleEntryRelay 把 addr 设为本节点的唯一入口 relay（清掉 bootstrap 时的占位入口）。
func (n *NATNode) setSoleEntryRelay(addr string) {
	n.mu.Lock()
	n.entryRelays = map[string]struct{}{addr: {}}
	n.knownRelays[addr] = struct{}{}
	n.mu.Unlock()
}

// selectEntryRelay 是入口 relay 选择的纯逻辑（便于单测）:
//   - 候选 = relays 中地址非空、且不是 index 自身（addr != indexAddr）的「子 relay」;
//   - 候选按与 selfID 的 XOR 距离升序排序;
//   - 依次用 reachable 探测, 返回首个可达者（第二个返回值 true 表示选中子 relay）;
//   - 没有可达子 relay 时回退 indexAddr（第二个返回值 false）。
func selectEntryRelay(selfID p2pnode.NodeID, indexAddr string, relays []relayquery.Info, reachable func(addr string) bool) (string, bool) {
	type candidate struct {
		addr string
		dist *big.Int
	}
	var cands []candidate
	seen := map[string]bool{}
	for _, r := range relays {
		if r.Addr == "" || r.Addr == indexAddr || r.NodeID == "" {
			continue // 跳过空地址 / index 自身 / 无效条目
		}
		if seen[r.Addr] {
			continue
		}
		seen[r.Addr] = true
		cands = append(cands, candidate{addr: r.Addr, dist: selfID.XOR(p2pnode.NodeID(r.NodeID))})
	}
	sort.SliceStable(cands, func(i, j int) bool {
		return cands[i].dist.Cmp(cands[j].dist) < 0
	})
	for _, c := range cands {
		if reachable(c.addr) {
			return c.addr, true
		}
	}
	return indexAddr, false
}

// probeRelayReachable 用一次短超时 TCP 拨号探测 relay 是否可达（端口连得上即认为可注册）。
func probeRelayReachable(addr string) bool {
	conn, err := net.DialTimeout("tcp", addr, relayProbeTimeout)
	if err != nil {
		log.Printf("[natnode] relay %s 不可达: %v", addr, err)
		return false
	}
	_ = conn.Close()
	return true
}
