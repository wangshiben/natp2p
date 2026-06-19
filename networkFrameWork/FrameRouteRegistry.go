package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"sync"
)

// frameRouteEntry 描述一条从源 leg 到目标 leg 的路由：
//
//	dest   目标 leg 的 FrameRelayEndpoint，用于把帧写出去。
//	dstID  在目标 leg 上为这一条逻辑消息预分配的新 MessageId。
//	       同一条消息的所有后续帧都复用此 dstID，确保目标侧能正确重组。
type frameRouteEntry struct {
	dest  FrameRelayEndpoint
	dstID uint64
}

// clientRouteKey 是 client 侧路由表的复合 key。
// 之所以要带 connectionID：同一个 StreamGroup 下挂着多个 client leg，
// 每个 client 的 MessageId 都从小数开始，单看 MessageId 会互相撞车，
// 必须用「哪个 client + 它的 MessageId」才能唯一定位一条路由。
type clientRouteKey struct {
	connectionID string
	messageID    uint64
}

// frameRouteRegistry 是「一个 StreamGroup 内、relay 与所有 client leg 之间」的双向路由表。
//
// pumpRelayToClients（relay->client）与 pumpClientToRelay（client->relay）共享同一份 registry，
// 这样一个方向建立的映射，反方向的 ACK 帧能复用，不会被当成新消息另起炉灶：
//
//	relaySide   key = relay leg 上的 MessageId        -> 转发到某个 client leg 的 entry
//	clientSide  key = {client connectionID, MessageId} -> 转发到 relay leg 的 entry
//
// 举例（client 发数据、relayServer 回 ACK）：
//   - client->relay：在 clientSide 记 {connID, srcMsgId}->relay(dstID)，
//     同时在 relaySide 记 dstID->client(srcMsgId) 作为反向回程。
//   - relayServer 的 ACK 经 relay leg 进来时，pumpRelayToClients 用 relaySide[ackMsgId]
//     就能直接查到「该回哪个 client、用哪个原始 MessageId」。
type frameRouteRegistry struct {
	mu         sync.Mutex
	relaySide  map[uint64]*frameRouteEntry
	clientSide map[clientRouteKey]*frameRouteEntry
}

func newFrameRouteRegistry() *frameRouteRegistry {
	return &frameRouteRegistry{
		relaySide:  make(map[uint64]*frameRouteEntry),
		clientSide: make(map[clientRouteKey]*frameRouteEntry),
	}
}

func (r *frameRouteRegistry) relayGet(messageID uint64) *frameRouteEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.relaySide[messageID]
}

func (r *frameRouteRegistry) relaySet(messageID uint64, entry *frameRouteEntry) {
	r.mu.Lock()
	r.relaySide[messageID] = entry
	r.mu.Unlock()
}

func (r *frameRouteRegistry) clientGet(connectionID string, messageID uint64) *frameRouteEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.clientSide[clientRouteKey{connectionID: connectionID, messageID: messageID}]
}

func (r *frameRouteRegistry) clientSet(connectionID string, messageID uint64, entry *frameRouteEntry) {
	r.mu.Lock()
	r.clientSide[clientRouteKey{connectionID: connectionID, messageID: messageID}] = entry
	r.mu.Unlock()
}

// newFrameRouteEntry 在第一次见到某个新 srcMessageId 时调用。
// 立即在目标 leg 上 AllocMessageId，使整条消息后续所有帧都映射到这个新 ID。
func newFrameRouteEntry(dest FrameRelayEndpoint) *frameRouteEntry {
	return &frameRouteEntry{dest: dest, dstID: dest.AllocMessageId()}
}

// parseFrameHeader 仅在 frame 是某条消息的首帧（SeqId == 0）时尝试解析其 Message Header。
//
// 返回 (Header, true) 表示这是一条业务首帧，relay 可以基于 Header.ConnectionId 决定路由；
// 返回 (nil, false) 的几种情况：
//   - frame == nil
//   - SeqId != 0：非首帧，relay 应该按已有映射跟随转发，无需再解析
//   - Payload 长度不足以容纳 Header
//   - Header 解析失败
//   - Header.RouteName == KeepAliveRoute：心跳包，不进入 relay 数据面
func parseFrameHeader(f *network.Frame) (*network.Header, bool) {
	if f == nil || f.SeqId != 0 || len(f.Payload) < network.HeaderLength {
		return nil, false
	}
	h, err := network.ParseHeader(f.Payload[:network.HeaderLength])
	if err != nil {
		return nil, false
	}
	if h.RouteName == KeepAliveRoute {
		return nil, false
	}
	return h, true
}

// pumpRelayToClients 是 relay->client 方向的 frame pump。
//
// 帧来源：relay leg（设备1 那侧）。帧去向：根据业务 ConnectionId 找到对应 client leg。
// 在 pure forwarder 模式下，这里搬运的既有数据帧，也有「设备1 回给 client 的 ACK 帧」。
//
// 路由复用 routes（与 pumpClientToRelay 共享）：
//   - relayGet(f.MessageId) 命中：说明这条 relay 侧 MessageId 已经有目标 client leg
//     （要么是设备1 主动发的数据流首帧建立的，要么是 client->relay 方向登记的反向回程）。
//   - 未命中：必须是数据流首帧（SeqId==0 且能解析出 Header），用 Header.ConnectionId
//     找到目标 client leg，分配 dstID 建正向映射，并登记反向回程（client 的 ACK 用得上）。
//
// 找不到目标 client（还没连上 / 已断开）就丢弃该帧。写失败则退出 pump。
// hookConfig 可选的转发 hook 配置，为 nil 则不启用 hook。
func pumpRelayToClients(ctx context.Context, relay FrameRelayEndpoint, lookup func(string) FrameRelayEndpoint, routes *frameRouteRegistry, hookConfig *ForwardHookConfig) {
	hookState := newForwardHookState(hookConfig)

	for {
		f, err := relay.NextFrame(ctx)
		if err != nil {
			return
		}

		// 调用 hook（如果配置了）
		if !hookState.onFrame(ctx, f, "relay_to_clients") {
			return
		}

		entry := routes.relayGet(f.MessageId)
		if entry == nil {
			// relay 侧第一次见到这个 MessageId：只接受能解析出业务 Header 的数据首帧。
			h, ok := parseFrameHeader(f)
			if !ok {
				continue
			}
			dst := lookup(h.ConnectionId)
			if dst == nil {
				continue
			}
			entry = newFrameRouteEntry(dst)
			// 正向：relay 的这个 MessageId -> 目标 client(dstID)。
			routes.relaySet(f.MessageId, entry)
			// 反向回程：client 用 dstID 回的 ACK -> 写回 relay leg 的原始 MessageId。
			routes.clientSet(dst.ConnectionId(), entry.dstID, &frameRouteEntry{dest: relay, dstID: f.MessageId})
		}

		out := *f
		out.MessageId = entry.dstID
		if err := entry.dest.HandleFrame(ctx, &out); err != nil {
			return
		}
	}
}

// pumpClientToRelay 是 client->relay 方向的 frame pump。
//
// 帧来源：某条 client leg（设备2）。帧去向：固定为本 group 的 relay leg（设备1）。
// pure forwarder 模式下，这里既转发 client 发的数据帧，也转发「client 回给设备1 的 ACK 帧」。
//
// 路由复用 routes（与 pumpRelayToClients 共享，用 connectionID 区分不同 client）：
//   - clientGet({connID, f.MessageId}) 命中：复用已有映射（含 relay->client 方向登记的反向回程）。
//   - 未命中：必须是数据首帧（SeqId==0），在 relay leg 上分配 dstID 建正向映射，
//     并登记反向回程（relayServer 的 ACK 用 dstID 回来时，能查回这个 client）。
//
// 写失败则退出 pump。
// hookConfig 可选的转发 hook 配置，为 nil 则不启用 hook。
func pumpClientToRelay(ctx context.Context, client FrameRelayEndpoint, relay FrameRelayEndpoint, routes *frameRouteRegistry, hookConfig *ForwardHookConfig) {
	hookState := newForwardHookState(hookConfig)

	for {
		f, err := client.NextFrame(ctx)
		if err != nil {
			if bridgeDebug {
				logBridge("C2R NextFrame 退出 connId=%s err=%v", client.ConnectionId(), err)
			}
			return
		}
		if bridgeDebug {
			logBridge("C2R got frame connId=%s msg=%d seq=%d type=%d", client.ConnectionId(), f.MessageId, f.SeqId, f.FrameType)
		}

		// 调用 hook（如果配置了）
		if !hookState.onFrame(ctx, f, "client_to_relay") {
			if bridgeDebug {
				logBridge("C2R hook 返回 error，停止转发 connId=%s", client.ConnectionId())
			}
			return
		}

		entry := routes.clientGet(client.ConnectionId(), f.MessageId)
		if entry == nil {
			if f.SeqId != 0 {
				continue
			}
			entry = newFrameRouteEntry(relay)
			// 正向：client 的这个 MessageId -> relay leg(dstID)。
			routes.clientSet(client.ConnectionId(), f.MessageId, entry)
			// 反向回程：relay 用 dstID 回的 ACK -> 写回该 client 的原始 MessageId。
			routes.relaySet(entry.dstID, &frameRouteEntry{dest: client, dstID: f.MessageId})
		}

		out := *f
		out.MessageId = entry.dstID
		if err := entry.dest.HandleFrame(ctx, &out); err != nil {
			if bridgeDebug {
				logBridge("C2R HandleFrame->relay 失败 connId=%s err=%v", client.ConnectionId(), err)
			}
			return
		}
	}
}
