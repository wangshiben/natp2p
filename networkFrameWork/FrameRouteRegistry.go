package networkFrameWork

import (
	"bnfs_p2p/logx"
	"bnfs_p2p/network"
	"container/list"
	"context"
	"sync"
	"time"
)

const (
	frameRouteTombstoneTTL = 90 * time.Second
	frameRouteMaxPairs     = 131072
)

// frameRouteEntry 描述一条从源 leg 到目标 leg 的路由：
//
//	dest   目标 leg 的 FrameRelayEndpoint，用于把帧写出去。
//	dstID  在目标 leg 上为这一条逻辑消息预分配的新 MessageId。
//	       同一条消息的所有后续帧都复用此 dstID，确保目标侧能正确重组。
type frameRouteEntry struct {
	dest  FrameRelayEndpoint
	dstID uint64
	pair  *frameRoutePair
}

// clientRouteKey 是 client 侧路由表的复合 key。
// 之所以要带 connectionID：同一个 StreamGroup 下挂着多个 client leg，
// 每个 client 的 MessageId 都从小数开始，单看 MessageId 会互相撞车，
// 必须用「哪个 client + 它的 MessageId」才能唯一定位一条路由。
type clientRouteKey struct {
	connectionID string
	messageID    uint64
}

type frameRoutePair struct {
	relayID     uint64
	clientKey   clientRouteKey
	relayEntry  *frameRouteEntry
	clientEntry *frameRouteEntry
	totalFrames uint32
	completed   bool
	expiresAt   time.Time
	expiryItem  *list.Element
	removed     bool
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
	mu              sync.Mutex
	relaySide       map[uint64]*frameRouteEntry
	clientSide      map[clientRouteKey]*frameRouteEntry
	connectionPairs map[string]map[*frameRoutePair]struct{}
	expiry          *list.List
	pairCount       int
	tombstoneTTL    time.Duration
	maxPairs        int
	now             func() time.Time
}

func newFrameRouteRegistry() *frameRouteRegistry {
	return newFrameRouteRegistryWithLimits(frameRouteTombstoneTTL, frameRouteMaxPairs)
}

func newFrameRouteRegistryWithLimits(ttl time.Duration, maxPairs int) *frameRouteRegistry {
	if ttl <= 0 {
		ttl = frameRouteTombstoneTTL
	}
	if maxPairs <= 0 {
		maxPairs = frameRouteMaxPairs
	}
	return &frameRouteRegistry{
		relaySide:       make(map[uint64]*frameRouteEntry),
		clientSide:      make(map[clientRouteKey]*frameRouteEntry),
		connectionPairs: make(map[string]map[*frameRoutePair]struct{}),
		expiry:          list.New(),
		tombstoneTTL:    ttl,
		maxPairs:        maxPairs,
		now:             time.Now,
	}
}

func (r *frameRouteRegistry) relayGet(messageID uint64) *frameRouteEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.expireLocked(now)
	entry := r.relaySide[messageID]
	if entry != nil {
		r.touchLocked(entry.pair, now)
	}
	return entry
}

func (r *frameRouteRegistry) clientGet(connectionID string, messageID uint64) *frameRouteEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.expireLocked(now)
	entry := r.clientSide[clientRouteKey{connectionID: connectionID, messageID: messageID}]
	if entry != nil {
		r.touchLocked(entry.pair, now)
	}
	return entry
}

func (r *frameRouteRegistry) bindPair(relayID uint64, relayEntry *frameRouteEntry, clientKey clientRouteKey, clientEntry *frameRouteEntry, totalFrames uint32) (*frameRoutePair, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.expireLocked(now)
	relayMatch := r.relaySide[relayID]
	clientMatch := r.clientSide[clientKey]
	if relayMatch != nil || clientMatch != nil {
		if relayMatch != nil && clientMatch != nil && relayMatch.pair == clientMatch.pair {
			pair := relayMatch.pair
			if pair != nil && pair.relayID == relayID && pair.clientKey == clientKey && pair.totalFrames == totalFrames {
				r.touchLocked(pair, now)
				return pair, true
			}
		}
		return nil, false
	}
	for r.pairCount >= r.maxPairs {
		if !r.evictOldestCompletedLocked() {
			return nil, false
		}
	}
	pair := &frameRoutePair{
		relayID:     relayID,
		clientKey:   clientKey,
		relayEntry:  relayEntry,
		clientEntry: clientEntry,
		totalFrames: totalFrames,
	}
	relayEntry.pair = pair
	clientEntry.pair = pair
	r.relaySide[relayID] = relayEntry
	r.clientSide[clientKey] = clientEntry
	r.pairCount++
	connectionSet := r.connectionPairs[clientKey.connectionID]
	if connectionSet == nil {
		connectionSet = make(map[*frameRoutePair]struct{})
		r.connectionPairs[clientKey.connectionID] = connectionSet
	}
	connectionSet[pair] = struct{}{}
	r.touchLocked(pair, now)
	return pair, true
}

func (r *frameRouteRegistry) complete(entry *frameRouteEntry) {
	if entry == nil || entry.pair == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	pair := entry.pair
	if pair.removed {
		return
	}
	now := r.now()
	pair.completed = true
	r.touchLocked(pair, now)
	r.expireLocked(now)
}

func (r *frameRouteRegistry) purgeConnection(connectionID string) {
	if connectionID == "" {
		return
	}
	r.mu.Lock()
	for pair := range r.connectionPairs[connectionID] {
		r.removePairLocked(pair)
	}
	delete(r.connectionPairs, connectionID)
	r.mu.Unlock()
}

func (r *frameRouteRegistry) clear() {
	r.mu.Lock()
	for item := r.expiry.Front(); item != nil; item = item.Next() {
		pair := item.Value.(*frameRoutePair)
		pair.removed = true
		pair.expiryItem = nil
	}
	r.relaySide = make(map[uint64]*frameRouteEntry)
	r.clientSide = make(map[clientRouteKey]*frameRouteEntry)
	r.connectionPairs = make(map[string]map[*frameRoutePair]struct{})
	r.expiry.Init()
	r.pairCount = 0
	r.mu.Unlock()
}

func (r *frameRouteRegistry) touchLocked(pair *frameRoutePair, now time.Time) {
	if pair == nil || pair.removed {
		return
	}
	if pair.expiryItem != nil {
		r.expiry.Remove(pair.expiryItem)
		pair.expiryItem = nil
	}
	pair.expiresAt = time.Time{}
	if !pair.completed {
		return
	}
	pair.expiresAt = now.Add(r.tombstoneTTL)
	pair.expiryItem = r.expiry.PushBack(pair)
}

func (r *frameRouteRegistry) expireLocked(now time.Time) {
	for {
		front := r.expiry.Front()
		if front == nil {
			return
		}
		pair := front.Value.(*frameRoutePair)
		if !pair.completed {
			r.expiry.Remove(front)
			pair.expiryItem = nil
			pair.expiresAt = time.Time{}
			continue
		}
		if pair.expiresAt.After(now) {
			return
		}
		r.removePairLocked(pair)
	}
}

func (r *frameRouteRegistry) evictOldestCompletedLocked() bool {
	for item := r.expiry.Front(); item != nil; item = item.Next() {
		pair := item.Value.(*frameRoutePair)
		if pair.completed {
			r.removePairLocked(pair)
			return true
		}
	}
	return false
}

func (r *frameRouteRegistry) removePairLocked(pair *frameRoutePair) {
	if pair == nil || pair.removed {
		return
	}
	if entry := r.relaySide[pair.relayID]; entry != nil && entry.pair == pair {
		delete(r.relaySide, pair.relayID)
	}
	if entry := r.clientSide[pair.clientKey]; entry != nil && entry.pair == pair {
		delete(r.clientSide, pair.clientKey)
	}
	if pair.expiryItem != nil {
		r.expiry.Remove(pair.expiryItem)
		pair.expiryItem = nil
	}
	if connectionSet := r.connectionPairs[pair.clientKey.connectionID]; connectionSet != nil {
		delete(connectionSet, pair)
		if len(connectionSet) == 0 {
			delete(r.connectionPairs, pair.clientKey.connectionID)
		}
	}
	pair.removed = true
	if r.pairCount > 0 {
		r.pairCount--
	}
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

type relayFrameWriteBatch struct {
	entry           *frameRouteEntry
	source          []*network.Frame
	forwarded       []*network.Frame
	accountedBytes  int64
	accountedFrames int64
}

func (b *relayFrameWriteBatch) empty() bool {
	return b == nil || len(b.forwarded) == 0
}

func (b *relayFrameWriteBatch) reset() {
	b.entry = nil
	b.source = b.source[:0]
	b.forwarded = b.forwarded[:0]
	b.accountedBytes = 0
	b.accountedFrames = 0
}

func canBatchRelayFrames(first, next *network.Frame) bool {
	if first == nil || next == nil || !isRelayBatchDataFrame(first) || !isRelayBatchDataFrame(next) {
		return false
	}
	return first.MessageId == next.MessageId && first.ConnectionId == next.ConnectionId && first.TotalFrames == next.TotalFrames
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
func pumpRelayToClients(ctx context.Context, relay FrameRelayEndpoint, lookup func(string) FrameRelayEndpoint, routes *frameRouteRegistry, hookConfig *ForwardHookConfig, nodeID string, onClientFailure func(string, FrameRelayEndpoint), registrationSessionID ...string) {
	hookState := newForwardHookState(hookConfig, nodeID, registrationSessionID...)
	batch := relayFrameWriteBatch{
		source:    make([]*network.Frame, 0, defaultRelayBatchMaxFrames),
		forwarded: make([]*network.Frame, 0, defaultRelayBatchMaxFrames),
	}
	flush := func() {
		if batch.empty() {
			return
		}
		entry := batch.entry
		if err := writeEndpointFrameBatch(ctx, entry.dest, batch.forwarded); err != nil {
			hookState.rollbackUncommitted(batch.accountedBytes, batch.accountedFrames)
			connectionID := entry.dest.ConnectionId()
			if entry.pair != nil {
				connectionID = entry.pair.clientKey.connectionID
			}
			if hookConfig != nil {
				hookConfig.ensureRetransmitCache().forgetConnection(hookState.holdbackScopeID, connectionID)
				hookState.resetHeldConnection(connectionID)
			}
			if onClientFailure != nil {
				onClientFailure(connectionID, entry.dest)
			} else {
				routes.purgeConnection(connectionID)
			}
			batch.reset()
			return
		}
		for _, source := range batch.source {
			if entry.pair != nil && isFullFrameAck(source, entry.pair.totalFrames) {
				routes.complete(entry)
			}
		}
		batch.reset()
	}
	rejectConnection := func(frame *network.Frame, err error) {
		flush()
		connectionID := ""
		messageID := uint64(0)
		sequenceID := uint32(0)
		if frame != nil {
			connectionID = frame.ConnectionId
			messageID = frame.MessageId
			sequenceID = frame.SeqId
		}
		logx.Warnf(
			"[billing-holdback] 拒绝并关闭业务连接: nodeId=%.16q connectionId=%s messageId=%d frameSeq=%d direction=relay_to_clients errorType=%T err=%q",
			nodeID, connectionID, messageID, sequenceID, err, err,
		)
		hookState.rejectRecord(ctx, frame, "relay_to_clients", err)
		if connectionID == "" {
			return
		}
		destination := lookup(connectionID)
		routes.purgeConnection(connectionID)
		if hookConfig != nil {
			hookConfig.ensureRetransmitCache().forgetConnection(hookState.holdbackScopeID, connectionID)
			hookState.forgetHeldConnection(connectionID)
		}
		if destination == nil {
			return
		}
		if onClientFailure != nil {
			onClientFailure(connectionID, destination)
			return
		}
		_ = destination.Close()
	}

	for {
		frames, err := nextEndpointFrameBatch(ctx, relay)
		if err != nil {
			flush()
			return
		}
		for _, incoming := range frames {
			if incoming == nil {
				continue
			}
			if incoming.FrameType == network.FrameTypeConnectionClose {
				flush()
				connectionID := incoming.ConnectionId
				destination := lookup(connectionID)
				routes.purgeConnection(connectionID)
				if destination == nil {
					continue
				}
				out := cloneFrame(incoming)
				out.MessageId = destination.AllocMessageId()
				if err := destination.HandleFrame(ctx, out); err != nil && onClientFailure != nil {
					onClientFailure(connectionID, destination)
				}
				continue
			}
			if hookState.billableRecordRequired("relay_to_clients") && isRelayBatchDataFrame(incoming) && lookup(incoming.ConnectionId) == nil {
				continue
			}
			authorized, authorizeErr := hookState.framesForForward(ctx, incoming, "relay_to_clients")
			for _, f := range authorized {
				billingBoundary := hookState.wouldInvokeHook(f)
				if !batch.empty() && (!canBatchRelayFrames(batch.source[0], f) || billingBoundary) {
					flush()
				}

				// hook 仍按原始 FIFO 每帧执行；可能触发外部计费的帧保持单帧写边界。
				beforeBytes, beforeFrames := hookState.pendingAccounting()
				if !hookState.onFrame(ctx, f, "relay_to_clients") {
					flush()
					return
				}
				afterBytes, afterFrames := hookState.pendingAccounting()

				entry := routes.relayGet(f.MessageId)
				if entry == nil {
					// 每帧自带 ConnectionId，不依赖首帧 payload 可解析或有序到达。
					connID := f.ConnectionId
					if connID == "" {
						continue
					}
					dst := lookup(connID)
					if dst == nil {
						continue
					}
					newEntry := newFrameRouteEntry(dst)
					pair, ok := routes.bindPair(
						f.MessageId,
						newEntry,
						clientRouteKey{connectionID: dst.ConnectionId(), messageID: newEntry.dstID},
						&frameRouteEntry{dest: relay, dstID: f.MessageId},
						f.TotalFrames,
					)
					if !ok {
						continue
					}
					entry = pair.relayEntry
				}

				if !batch.empty() && batch.entry != entry {
					flush()
				}
				out := *f
				out.MessageId = entry.dstID
				batch.entry = entry
				batch.source = append(batch.source, f)
				batch.forwarded = append(batch.forwarded, &out)
				if !billingBoundary {
					batch.accountedBytes += afterBytes - beforeBytes
					batch.accountedFrames += afterFrames - beforeFrames
				}
				if !isRelayBatchDataFrame(f) || billingBoundary {
					flush()
				}
			}
			if authorizeErr != nil {
				rejectConnection(incoming, authorizeErr)
			}
		}
		flush()
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
func pumpClientToRelay(ctx context.Context, client FrameRelayEndpoint, relay FrameRelayEndpoint, routes *frameRouteRegistry, hookConfig *ForwardHookConfig, nodeID string, registrationSessionID ...string) {
	hookState := newForwardHookState(hookConfig, nodeID, registrationSessionID...)
	batch := relayFrameWriteBatch{
		source:    make([]*network.Frame, 0, defaultRelayBatchMaxFrames),
		forwarded: make([]*network.Frame, 0, defaultRelayBatchMaxFrames),
	}
	flush := func() bool {
		if batch.empty() {
			return true
		}
		entry := batch.entry
		if err := writeEndpointFrameBatch(ctx, entry.dest, batch.forwarded); err != nil {
			if bridgeDebug {
				logBridge("C2R HandleFrameBatch->relay 失败 connId=%s frames=%d err=%v", client.ConnectionId(), len(batch.forwarded), err)
			}
			batch.reset()
			return false
		}
		for _, source := range batch.source {
			if source.FrameType == network.FrameTypeAck && hookConfig != nil {
				if ranges, err := network.DecodeAckRanges(source.Payload); err == nil && len(ranges) > 0 {
					hookConfig.ensureRetransmitCache().acknowledge(
						hookState.holdbackScopeID, client.ConnectionId(), entry.dstID, source.TotalFrames, ranges,
					)
				}
			}
			if entry.pair != nil && isFullFrameAck(source, entry.pair.totalFrames) {
				hookState.acknowledgeHeldMessage(client.ConnectionId(), entry.dstID)
				routes.complete(entry)
			}
		}
		batch.reset()
		return true
	}

	for {
		frames, err := nextEndpointFrameBatch(ctx, client)
		if err != nil {
			if bridgeDebug {
				logBridge("C2R NextFrame 退出 connId=%s err=%v", client.ConnectionId(), err)
			}
			_ = flush()
			return
		}
		for _, f := range frames {
			if f == nil {
				continue
			}
			if f.FrameType == network.FrameTypeConnectionClose {
				if !flush() {
					return
				}
				out := cloneFrame(f)
				out.MessageId = relay.AllocMessageId()
				if err := relay.HandleFrame(ctx, out); err != nil {
					return
				}
				routes.purgeConnection(client.ConnectionId())
				continue
			}
			if bridgeDebug {
				logBridge("C2R got frame connId=%s msg=%d seq=%d type=%d", client.ConnectionId(), f.MessageId, f.SeqId, f.FrameType)
			}
			billingBoundary := hookState.wouldInvokeHook(f)
			if !batch.empty() && (!canBatchRelayFrames(batch.source[0], f) || billingBoundary) {
				if !flush() {
					return
				}
			}

			if !hookState.onFrame(ctx, f, "client_to_relay") {
				if bridgeDebug {
					logBridge("C2R hook 返回 error，停止转发 connId=%s", client.ConnectionId())
				}
				_ = flush()
				return
			}

			entry := routes.clientGet(client.ConnectionId(), f.MessageId)
			if entry == nil {
				if f.FrameType == network.FrameTypeAck || f.SeqId != 0 {
					continue
				}
				newEntry := newFrameRouteEntry(relay)
				clientEntry := newEntry
				relayEntry := &frameRouteEntry{dest: client, dstID: f.MessageId}
				pair, ok := routes.bindPair(
					newEntry.dstID,
					relayEntry,
					clientRouteKey{connectionID: client.ConnectionId(), messageID: f.MessageId},
					clientEntry,
					f.TotalFrames,
				)
				if !ok {
					continue
				}
				entry = pair.clientEntry
			}
			if !batch.empty() && batch.entry != entry {
				if !flush() {
					return
				}
			}
			out := *f
			out.MessageId = entry.dstID
			batch.entry = entry
			batch.source = append(batch.source, f)
			batch.forwarded = append(batch.forwarded, &out)
			if !isRelayBatchDataFrame(f) || billingBoundary {
				if !flush() {
					return
				}
			}
		}
		if !flush() {
			return
		}
	}
}
