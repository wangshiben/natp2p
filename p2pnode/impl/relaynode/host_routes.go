package relaynode

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"net"
	"sort"
	"sync"
	"time"

	"bnfs_p2p/admission"
	"bnfs_p2p/logx"
	"bnfs_p2p/networkFrameWork"
)

const (
	hostRouteLease                  = 45 * time.Second
	hostRouteRenewPeriod            = 15 * time.Second
	hostRouteClockSkew              = 30 * time.Second
	maximumHostRouteBatch           = 128
	maximumHostRoutePath            = 8
	maximumHostRouteTargets         = 65536
	maximumHostRoutesPerTarget      = 32
	hostRouteBroadcastTimeout       = 3 * time.Second
	hostRouteBroadcastWorkers       = 8
	hostRouteBroadcastQueueCapacity = 256
)

type hostRouteRecord struct {
	wire hostRouteWire
	via  string
}

type hostRouteSignature struct {
	Target         string `json:"target"`
	RelayID        string `json:"relay_id"`
	RelayPublicKey string `json:"relay_public_key"`
	Addr           string `json:"addr"`
	Incarnation    string `json:"incarnation"`
	Sequence       uint64 `json:"sequence"`
	IssuedAt       int64  `json:"issued_at"`
	LeaseUntil     int64  `json:"lease_until"`
	Active         bool   `json:"active"`
}

func (n *RelayNode) maintainHostRoutes() {
	ticker := time.NewTicker(hostRouteRenewPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-n.ctx.Done():
			return
		case <-ticker.C:
		}
		for _, peer := range n.HostedNatNodes() {
			n.publishLocalHostRoute(string(peer.ID), true)
		}
		n.expireHostRoutes(time.Now())
	}
}

func (n *RelayNode) publishLocalHostRoute(target string, active bool) {
	if target == "" {
		return
	}
	n.mu.Lock()
	n.hostRouteSequence[target]++
	sequence := n.hostRouteSequence[target]
	n.mu.Unlock()
	now := time.Now()
	route := hostRouteWire{
		Target: target, RelayID: n.idStr(), RelayPublicKey: n.pubKeyHex(), Addr: n.getAddr(),
		Incarnation: n.hostRouteIncarnation, Sequence: sequence, IssuedAt: now.UnixNano(),
		LeaseUntil: now.Add(hostRouteLease).UnixNano(), Active: active, IndexSign: n.selfCertJSON(),
		Path: []string{n.idStr()},
	}
	signature, err := signHostRoute(n.privKey, route)
	if err != nil {
		logx.Warnf("[relay-route] 签署托管公告失败: target=%.16s err=%v", target, err)
		return
	}
	route.Signature = signature
	n.acceptHostRoute("", route)
	n.broadcastHostRoutes([]hostRouteWire{route}, "")
}

func (n *RelayNode) syncHostRoutes(link *peerLink) {
	if link == nil {
		return
	}
	routes := n.hostRouteSnapshot(time.Now())
	for len(routes) > 0 {
		batchSize := min(len(routes), maximumHostRouteBatch)
		if err := link.send(&controlMessage{Type: ctrlHostRoutes, Routes: routes[:batchSize]}); err != nil {
			return
		}
		routes = routes[batchSize:]
	}
}

func (n *RelayNode) receiveHostRoutes(link *peerLink, routes []hostRouteWire) {
	if link == nil || len(routes) == 0 || len(routes) > maximumHostRouteBatch {
		return
	}
	link.mu.Lock()
	via := link.peerID
	link.mu.Unlock()
	if via == "" {
		return
	}
	forward := make([]hostRouteWire, 0, len(routes))
	for _, route := range routes {
		if containsRelay(route.Path, n.idStr()) || len(route.Path) >= maximumHostRoutePath {
			continue
		}
		route.Path = append(append([]string(nil), route.Path...), n.idStr())
		accepted, becameMultipath := n.acceptHostRoute(via, route)
		if !accepted {
			continue
		}
		if becameMultipath {
			forward = append(forward, n.transitHostRouteSnapshot(route.Target, time.Now())...)
		} else if n.hostRouteTransitEnabled(route.Target) {
			forward = append(forward, route)
		}
	}
	if len(forward) > 0 {
		n.broadcastHostRoutes(forward, via)
	}
}

func (n *RelayNode) acceptHostRoute(via string, route hostRouteWire) (bool, bool) {
	if err := n.verifyHostRoute(route); err != nil {
		logx.Warnf("[relay-route] 拒绝托管公告: origin=%.16s target=%.16s err=%v", route.RelayID, route.Target, err)
		return false, false
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	byRelay := n.hostRoutes[route.Target]
	if byRelay == nil {
		if len(n.hostRoutes) >= maximumHostRouteTargets {
			return false, false
		}
		byRelay = make(map[string]hostRouteRecord)
		n.hostRoutes[route.Target] = byRelay
	}
	current, exists := byRelay[route.RelayID]
	if exists && !newerHostRoute(current.wire, route) {
		return false, false
	}
	if !exists && len(byRelay) >= maximumHostRoutesPerTarget {
		return false, false
	}
	byRelay[route.RelayID] = hostRouteRecord{wire: cloneHostRoute(route), via: via}
	becameMultipath := false
	if !n.hostRouteMultipath[route.Target] && activeHostRouteCount(byRelay, time.Now()) >= 2 {
		n.hostRouteMultipath[route.Target] = true
		becameMultipath = true
	}
	return true, becameMultipath
}

func (n *RelayNode) verifyHostRoute(route hostRouteWire) error {
	now := time.Now()
	if route.Target == "" || route.RelayID == "" || route.RelayPublicKey == "" || route.Addr == "" ||
		route.Incarnation == "" || route.Sequence == 0 || route.IssuedAt == 0 || route.LeaseUntil == 0 {
		return errors.New("missing required route field")
	}
	if !canonicalNodeID(route.Target) || !canonicalNodeID(route.RelayID) {
		return errors.New("route contains a non-canonical NodeID")
	}
	if len(route.RelayPublicKey) != 130 || len(route.Addr) > 512 || len(route.Incarnation) > 128 ||
		len(route.Path) > maximumHostRoutePath || len(route.Signature) > 80 || len(route.IndexSign) > 64*1024 {
		return errors.New("route field exceeds its size limit")
	}
	for _, relayID := range route.Path {
		if !canonicalNodeID(relayID) {
			return errors.New("route path contains a non-canonical Relay ID")
		}
	}
	if networkFrameWork.NodeIDFromPubKeyHex(route.RelayPublicKey) != route.RelayID {
		return errors.New("Relay identity does not match public key")
	}
	if _, _, err := net.SplitHostPort(route.Addr); err != nil {
		return errors.New("invalid Relay address")
	}
	issuedAt := time.Unix(0, route.IssuedAt)
	leaseUntil := time.Unix(0, route.LeaseUntil)
	if issuedAt.After(now.Add(hostRouteClockSkew)) || leaseUntil.Before(now.Add(-hostRouteClockSkew)) ||
		leaseUntil.Sub(issuedAt) > hostRouteLease+hostRouteClockSkew {
		return errors.New("route lease is outside the accepted window")
	}
	if n.admissionEnabled() {
		cert, err := n.verifyPeerCertJSON(route.IndexSign, admission.RoleRelay, route.RelayID)
		if !n.gateAdmission(cert, err, "host-route "+route.RelayID[:min(16, len(route.RelayID))]) {
			return errors.New("route origin is not admitted")
		}
	}
	return verifyHostRouteSignature(route)
}

func (n *RelayNode) broadcastHostRoutes(routes []hostRouteWire, exceptPeerID string) {
	if len(routes) == 0 {
		return
	}
	n.broadcastControl(&controlMessage{Type: ctrlHostRoutes, Routes: routes}, exceptPeerID)
}

func (n *RelayNode) broadcastControl(message *controlMessage, exceptPeerID string) {
	if message == nil || n.ctx.Err() != nil {
		return
	}
	event := hostRouteBroadcastEvent{
		message:      cloneBroadcastControlMessage(message),
		exceptPeerID: exceptPeerID,
	}
	select {
	case n.hostRouteBroadcastQueue <- event:
	default:
		dropped := n.hostRouteBroadcastDropped.Add(1)
		// 只按 2 的幂次告警，既保留持续过载证据，也避免告警本身放大控制面压力。
		if dropped == 1 || dropped&(dropped-1) == 0 {
			logx.Warnf("[relay-route] 广播队列已满，丢弃可续期软状态: type=%s dropped=%d capacity=%d",
				message.Type, dropped, cap(n.hostRouteBroadcastQueue))
		}
	}
}

func (n *RelayNode) runHostRouteBroadcasts() {
	defer close(n.hostRouteBroadcastDone)
	var pending *hostRouteBroadcastEvent
	for {
		if n.ctx.Err() != nil {
			return
		}
		var event hostRouteBroadcastEvent
		if pending != nil {
			event = *pending
			pending = nil
		} else {
			select {
			case <-n.ctx.Done():
				return
			case event = <-n.hostRouteBroadcastQueue:
			}
		}
		event, pending = n.mergeQueuedHostRouteBroadcasts(event)
		n.deliverBroadcastControl(event.message, event.exceptPeerID)
	}
}

// mergeQueuedHostRouteBroadcasts 将相邻且同方向的托管路由事件合成一个最多 128 条的批次。
// 队列仍由单 worker 严格按序消费，因此同一目标的 offline -> online 代次不会被重排；
// 周期续期也不会因一个异常邻居而变成每目标一次 3 秒超时。
func (n *RelayNode) mergeQueuedHostRouteBroadcasts(first hostRouteBroadcastEvent) (hostRouteBroadcastEvent, *hostRouteBroadcastEvent) {
	for broadcastControlItemCount(first.message) < maximumHostRouteBatch {
		select {
		case next := <-n.hostRouteBroadcastQueue:
			if !mergeBroadcastControlMessage(first.message, next.message, first.exceptPeerID, next.exceptPeerID) {
				return first, &next
			}
		default:
			return first, nil
		}
	}
	return first, nil
}

func broadcastControlItemCount(message *controlMessage) int {
	if message == nil {
		return 0
	}
	switch message.Type {
	case ctrlHostRoutes:
		return len(message.Routes)
	case ctrlHostWithdraw:
		return len(message.Withdrawals)
	default:
		return maximumHostRouteBatch
	}
}

func mergeBroadcastControlMessage(destination, source *controlMessage, destinationExcept, sourceExcept string) bool {
	if destination == nil || source == nil || destination.Type != source.Type || destinationExcept != sourceExcept {
		return false
	}
	switch destination.Type {
	case ctrlHostRoutes:
		if len(destination.Routes)+len(source.Routes) > maximumHostRouteBatch {
			return false
		}
		destination.Routes = append(destination.Routes, source.Routes...)
		return true
	case ctrlHostWithdraw:
		if len(destination.Withdrawals)+len(source.Withdrawals) > maximumHostRouteBatch {
			return false
		}
		destination.Withdrawals = append(destination.Withdrawals, source.Withdrawals...)
		return true
	default:
		return false
	}
}

func cloneBroadcastControlMessage(message *controlMessage) *controlMessage {
	if message == nil {
		return nil
	}
	cloned := *message
	cloned.IndexSign = append([]byte(nil), message.IndexSign...)
	cloned.Routes = make([]hostRouteWire, len(message.Routes))
	for index, route := range message.Routes {
		cloned.Routes[index] = cloneHostRoute(route)
	}
	cloned.Withdrawals = append([]hostRouteKey(nil), message.Withdrawals...)
	return &cloned
}

func (n *RelayNode) deliverBroadcastControl(message *controlMessage, exceptPeerID string) {
	n.mu.RLock()
	links := make([]*peerLink, 0, len(n.peerLinks)+len(n.inboundLinks))
	for _, link := range n.peerLinks {
		links = append(links, link)
	}
	links = append(links, n.inboundLinks...)
	n.mu.RUnlock()
	eligible := make([]*peerLink, 0, len(links))
	for _, link := range links {
		if link == nil {
			continue
		}
		link.mu.Lock()
		peerID := link.peerID
		link.mu.Unlock()
		if peerID == "" || peerID == exceptPeerID {
			continue
		}
		eligible = append(eligible, link)
	}
	if len(eligible) == 0 {
		return
	}

	// 使用共享截止时间和小型 worker pool 并行投递：单条坏控制链路最多拖慢本轮 3 秒，
	// 健康链路仍可同时收到事件；本函数仅由长期广播 worker 串行调用，事件内 worker
	// 数也有硬上限，因此邻居异常时不会制造 goroutine 风暴或反向阻塞 NAT 注册。
	ctx, cancel := context.WithTimeout(n.ctx, hostRouteBroadcastTimeout)
	defer cancel()
	jobs := make(chan *peerLink, len(eligible))
	for _, link := range eligible {
		jobs <- link
	}
	close(jobs)
	workers := min(hostRouteBroadcastWorkers, len(eligible))
	n.mu.RLock()
	send := n.hostRouteBroadcastSend
	n.mu.RUnlock()
	var wait sync.WaitGroup
	wait.Add(workers)
	for worker := 0; worker < workers; worker++ {
		go func() {
			defer wait.Done()
			for link := range jobs {
				if ctx.Err() != nil {
					return
				}
				_ = send(ctx, link, message)
			}
		}()
	}
	done := make(chan struct{})
	go func() {
		wait.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (n *RelayNode) hostRouteSnapshot(now time.Time) []hostRouteWire {
	n.mu.RLock()
	defer n.mu.RUnlock()
	routes := make([]hostRouteWire, 0)
	for target, byRelay := range n.hostRoutes {
		for _, record := range byRelay {
			if record.wire.Active && now.Before(time.Unix(0, record.wire.LeaseUntil)) &&
				(record.via == "" || n.hostRouteMultipath[target]) {
				routes = append(routes, cloneHostRoute(record.wire))
			}
		}
	}
	return routes
}

func (n *RelayNode) transitHostRouteSnapshot(target string, now time.Time) []hostRouteWire {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if !n.hostRouteMultipath[target] {
		return nil
	}
	routes := make([]hostRouteWire, 0, len(n.hostRoutes[target]))
	for _, record := range n.hostRoutes[target] {
		if record.wire.Active && now.Before(time.Unix(0, record.wire.LeaseUntil)) {
			routes = append(routes, cloneHostRoute(record.wire))
		}
	}
	return routes
}

func (n *RelayNode) hostRouteTransitEnabled(target string) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.hostRouteMultipath[target]
}

func activeHostRouteCount(byRelay map[string]hostRouteRecord, now time.Time) int {
	count := 0
	for _, record := range byRelay {
		if record.wire.Active && now.Before(time.Unix(0, record.wire.LeaseUntil)) {
			count++
		}
	}
	return count
}

func (n *RelayNode) expireHostRoutes(now time.Time) {
	n.mu.Lock()
	for target, byRelay := range n.hostRoutes {
		for relayID, record := range byRelay {
			if !now.Before(time.Unix(0, record.wire.LeaseUntil)) {
				delete(byRelay, relayID)
			}
		}
		if len(byRelay) == 0 {
			delete(n.hostRoutes, target)
			delete(n.hostRouteMultipath, target)
		}
	}
	n.mu.Unlock()
}

func (n *RelayNode) removeHostRoutesVia(peerID string) {
	if peerID == "" {
		return
	}
	n.mu.Lock()
	withdrawals := make([]hostRouteKey, 0)
	for target, byRelay := range n.hostRoutes {
		for relayID, record := range byRelay {
			if record.via == peerID {
				delete(byRelay, relayID)
				withdrawals = append(withdrawals, hostRouteKey{Target: target, RelayID: relayID})
			}
		}
		if len(byRelay) == 0 {
			delete(n.hostRoutes, target)
			delete(n.hostRouteMultipath, target)
		}
	}
	n.mu.Unlock()
	n.broadcastHostWithdrawals(withdrawals, peerID)
}

func (n *RelayNode) receiveHostWithdrawals(link *peerLink, withdrawals []hostRouteKey) {
	if link == nil || len(withdrawals) == 0 || len(withdrawals) > maximumHostRouteBatch {
		return
	}
	via := link.peerIdentity()
	if via == "" {
		return
	}
	removed := make([]hostRouteKey, 0, len(withdrawals))
	n.mu.Lock()
	for _, withdrawal := range withdrawals {
		if !canonicalNodeID(withdrawal.Target) || !canonicalNodeID(withdrawal.RelayID) {
			continue
		}
		byRelay := n.hostRoutes[withdrawal.Target]
		record, exists := byRelay[withdrawal.RelayID]
		if !exists || record.via != via {
			continue
		}
		delete(byRelay, withdrawal.RelayID)
		if len(byRelay) == 0 {
			delete(n.hostRoutes, withdrawal.Target)
			delete(n.hostRouteMultipath, withdrawal.Target)
		}
		removed = append(removed, withdrawal)
	}
	n.mu.Unlock()
	n.broadcastHostWithdrawals(removed, via)
}

func (n *RelayNode) broadcastHostWithdrawals(withdrawals []hostRouteKey, exceptPeerID string) {
	for len(withdrawals) > 0 {
		batchSize := min(len(withdrawals), maximumHostRouteBatch)
		n.broadcastControl(&controlMessage{Type: ctrlHostWithdraw, Withdrawals: withdrawals[:batchSize]}, exceptPeerID)
		withdrawals = withdrawals[batchSize:]
	}
}

func (n *RelayNode) routeNextHops(target, excludedPeerID string) []*peerLink {
	return n.routeNextHopsMatching(target, excludedPeerID, false)
}

func (n *RelayNode) transitRouteNextHops(target, excludedPeerID string) []*peerLink {
	return n.routeNextHopsMatching(target, excludedPeerID, true)
}

func (n *RelayNode) routeNextHopsMatching(target, excludedPeerID string, requireMultipath bool) []*peerLink {
	now := time.Now()
	n.mu.RLock()
	if requireMultipath && !n.hostRouteMultipath[target] {
		n.mu.RUnlock()
		return nil
	}
	records := make([]hostRouteRecord, 0, len(n.hostRoutes[target]))
	for _, record := range n.hostRoutes[target] {
		if record.wire.Active && now.Before(time.Unix(0, record.wire.LeaseUntil)) {
			records = append(records, record)
		}
	}
	n.mu.RUnlock()
	sort.SliceStable(records, func(left, right int) bool {
		return records[left].wire.RelayID < records[right].wire.RelayID
	})
	if len(records) > 1 {
		offset := int(n.hostRouteCursor.Add(1)-1) % len(records)
		records = append(records[offset:], records[:offset]...)
	}
	links := make([]*peerLink, 0, len(records))
	seen := make(map[*peerLink]struct{})
	for _, record := range records {
		if record.via == "" || record.via == excludedPeerID {
			continue
		}
		link := n.peerLinkByID(record.via)
		if link == nil {
			continue
		}
		if _, exists := seen[link]; exists {
			continue
		}
		seen[link] = struct{}{}
		links = append(links, link)
	}
	return links
}

func (n *RelayNode) peerLinkByID(peerID string) *peerLink {
	n.mu.RLock()
	links := make([]*peerLink, 0, len(n.peerLinks)+len(n.inboundLinks))
	for _, link := range n.peerLinks {
		links = append(links, link)
	}
	links = append(links, n.inboundLinks...)
	n.mu.RUnlock()
	for _, link := range links {
		if link != nil && link.peerIdentity() == peerID {
			return link
		}
	}
	return nil
}

func (pl *peerLink) peerIdentity() string {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	return pl.peerID
}

func newerHostRoute(current, incoming hostRouteWire) bool {
	if incoming.Incarnation != current.Incarnation {
		return incoming.IssuedAt > current.IssuedAt
	}
	return incoming.Sequence > current.Sequence
}

func containsRelay(path []string, relayID string) bool {
	for _, id := range path {
		if id == relayID {
			return true
		}
	}
	return false
}

func cloneHostRoute(route hostRouteWire) hostRouteWire {
	route.IndexSign = append([]byte(nil), route.IndexSign...)
	route.Path = append([]string(nil), route.Path...)
	route.Signature = append([]byte(nil), route.Signature...)
	return route
}

func hostRouteDigest(route hostRouteWire) ([sha256.Size]byte, error) {
	body, err := json.Marshal(hostRouteSignature{
		Target: route.Target, RelayID: route.RelayID, RelayPublicKey: route.RelayPublicKey, Addr: route.Addr,
		Incarnation: route.Incarnation, Sequence: route.Sequence, IssuedAt: route.IssuedAt,
		LeaseUntil: route.LeaseUntil, Active: route.Active,
	})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(append([]byte("BNFS/HOST-ROUTE/V1"), body...)), nil
}

func signHostRoute(identity *ecdh.PrivateKey, route hostRouteWire) ([]byte, error) {
	if identity == nil {
		return nil, errors.New("Relay identity is nil")
	}
	privateScalar := new(big.Int).SetBytes(identity.Bytes())
	if privateScalar.Sign() <= 0 || privateScalar.Cmp(elliptic.P256().Params().N) >= 0 {
		return nil, errors.New("invalid Relay identity scalar")
	}
	privateKey := &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256()}, D: privateScalar}
	privateKey.PublicKey.X, privateKey.PublicKey.Y = elliptic.P256().ScalarBaseMult(privateScalar.Bytes())
	digest, err := hostRouteDigest(route)
	if err != nil {
		return nil, err
	}
	return ecdsa.SignASN1(rand.Reader, privateKey, digest[:])
}

func canonicalNodeID(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func verifyHostRouteSignature(route hostRouteWire) error {
	publicBytes, err := hex.DecodeString(route.RelayPublicKey)
	if err != nil {
		return errors.New("invalid Relay public key encoding")
	}
	publicX, publicY := elliptic.Unmarshal(elliptic.P256(), publicBytes)
	if publicX == nil || publicY == nil {
		return errors.New("invalid Relay P-256 public key")
	}
	digest, err := hostRouteDigest(route)
	if err != nil {
		return err
	}
	if !ecdsa.VerifyASN1(&ecdsa.PublicKey{Curve: elliptic.P256(), X: publicX, Y: publicY}, digest[:], route.Signature) {
		return errors.New("invalid Relay route signature")
	}
	return nil
}
