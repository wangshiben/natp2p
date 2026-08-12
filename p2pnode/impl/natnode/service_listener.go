package natnode

import (
	"bnfs_p2p/DHTable"
	"bnfs_p2p/logx"
	"bnfs_p2p/network"
	"bnfs_p2p/networkFrameWork"
	"bnfs_p2p/networkFrameWork/client"
	"bnfs_p2p/p2pnode"

	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

const (
	defaultServiceMaxSessions       = 8
	defaultServiceAcceptQueue       = 8
	defaultServiceHandshakeTimeout  = 10 * time.Second
	maximumServiceRelays            = 3
	serviceConnectionTombstoneTTL   = 10 * time.Minute
	serviceConnectionTombstoneLimit = 4096
)

// ServiceOptions 配置 NatServer 持久服务注册。
// 注册载体持续存活，每个客户端获得按 connectionID 隔离的逻辑会话。
type ServiceOptions struct {
	MaxSessions      int
	AcceptQueue      int
	HandshakeTimeout time.Duration
}

// ServiceListener 从持久的 NatServer 到 Relay 载体接收独立入站服务会话。
type ServiceListener struct {
	node   *NATNode
	addr   string
	ctx    context.Context
	cancel context.CancelFunc

	options  ServiceOptions
	accepted chan p2pnode.Connection
	sessions chan struct{}

	mu              sync.Mutex
	relays          []string
	carriers        map[string]*serviceCarrier
	entry           *relayEntry
	mux             *networkFrameWork.EndpointFrameMux
	active          map[string]p2pnode.Connection
	sessionCarriers map[string]*serviceCarrier
	pending         map[string]*serviceCarrier
	retired         map[string]time.Time
	closed          bool
	closeOnce       sync.Once
	workers         sync.WaitGroup

	acceptedTotal   atomic.Uint64
	rejectedTotal   atomic.Uint64
	carrierSequence atomic.Uint64
}

type serviceCarrier struct {
	addr       string
	exact      bool
	entry      *relayEntry
	mux        *networkFrameWork.EndpointFrameMux
	generation uint64
}

type ServiceSessionSnapshot struct {
	ConnectionID string `json:"connectionId"`
	PeerID       string `json:"peerId"`
	RelayAddress string `json:"relayAddress,omitempty"`
}

type ServiceCarrierSnapshot struct {
	RelayAddress         string `json:"relayAddress"`
	Connected            bool   `json:"connected"`
	CarrierGeneration    uint64 `json:"carrierGeneration"`
	ActiveSessions       int    `json:"activeSessions"`
	DataQueueDepth       int    `json:"dataQueueDepth"`
	DataQueueCapacity    int    `json:"dataQueueCapacity"`
	ControlQueueDepth    int    `json:"controlQueueDepth"`
	ControlQueueCapacity int    `json:"controlQueueCapacity"`
}

type ServiceListenerSnapshot struct {
	RelayAddress      string                   `json:"relayAddress"`
	CarrierConnected  bool                     `json:"carrierConnected"`
	CarrierGeneration uint64                   `json:"carrierGeneration"`
	ActiveSessions    int                      `json:"activeSessions"`
	MaxSessions       int                      `json:"maxSessions"`
	AcceptQueueDepth  int                      `json:"acceptQueueDepth"`
	AcceptQueue       int                      `json:"acceptQueue"`
	AcceptedTotal     uint64                   `json:"acceptedTotal"`
	RejectedTotal     uint64                   `json:"rejectedTotal"`
	Carriers          []ServiceCarrierSnapshot `json:"carriers,omitempty"`
	Sessions          []ServiceSessionSnapshot `json:"sessions"`
}

// ListenService 将本节点注册为持久服务端点。
// 与 Listen 不同，客户端会话不会消耗或改变注册载体。
func (n *NATNode) ListenService(ctx context.Context, addr string, options ServiceOptions) (*ServiceListener, error) {
	return n.listenServiceRelays(ctx, []string{addr}, options, false)
}

// ListenServiceRelays 在每个指定 Relay 注册一条持久载体。
// 所有载体共享一个 Accept 队列和一个全局会话上限。
func (n *NATNode) ListenServiceRelays(ctx context.Context, relays []string, options ServiceOptions) (*ServiceListener, error) {
	return n.listenServiceRelays(ctx, relays, options, true)
}

func (n *NATNode) listenServiceRelays(ctx context.Context, relays []string, options ServiceOptions, exact bool) (*ServiceListener, error) {
	relays, err := normalizeServiceRelays(relays)
	if err != nil {
		return nil, err
	}
	options = normalizeServiceOptions(options)
	listenerCtx, cancel := context.WithCancel(ctx)
	listener := &ServiceListener{
		node:            n,
		addr:            relays[0],
		relays:          relays,
		ctx:             listenerCtx,
		cancel:          cancel,
		options:         options,
		accepted:        make(chan p2pnode.Connection, options.AcceptQueue),
		sessions:        make(chan struct{}, options.MaxSessions),
		active:          make(map[string]p2pnode.Connection),
		carriers:        make(map[string]*serviceCarrier, len(relays)),
		sessionCarriers: make(map[string]*serviceCarrier),
		pending:         make(map[string]*serviceCarrier),
		retired:         make(map[string]time.Time),
	}
	for _, relay := range relays {
		listener.carriers[relay] = &serviceCarrier{addr: relay, exact: exact}
	}

	go func() {
		select {
		case <-n.ctx.Done():
			_ = listener.Close()
		case <-listenerCtx.Done():
		}
	}()

	var openErrors []error
	opened := 0
	for _, relay := range relays {
		carrier := listener.carriers[relay]
		if err := listener.openCarrier(carrier); err != nil {
			openErrors = append(openErrors, err)
			continue
		}
		opened++
	}
	if opened == 0 {
		_ = listener.Close()
		return nil, errors.Join(openErrors...)
	}
	for _, relay := range relays {
		go listener.maintainCarrier(listener.carriers[relay])
	}
	return listener, nil
}

func normalizeServiceRelays(relays []string) ([]string, error) {
	unique := make([]string, 0, len(relays))
	seen := make(map[string]struct{}, len(relays))
	for _, relay := range relays {
		if relay == "" {
			continue
		}
		if _, exists := seen[relay]; exists {
			continue
		}
		seen[relay] = struct{}{}
		unique = append(unique, relay)
	}
	if len(unique) == 0 {
		return nil, errors.New("natnode: at least one service relay address is required")
	}
	if len(unique) > maximumServiceRelays {
		return nil, fmt.Errorf("natnode: service relay count %d exceeds maximum %d", len(unique), maximumServiceRelays)
	}
	return unique, nil
}

func normalizeServiceOptions(options ServiceOptions) ServiceOptions {
	if options.MaxSessions <= 0 {
		options.MaxSessions = defaultServiceMaxSessions
	}
	if options.AcceptQueue <= 0 {
		options.AcceptQueue = defaultServiceAcceptQueue
	}
	if options.HandshakeTimeout <= 0 {
		options.HandshakeTimeout = defaultServiceHandshakeTimeout
	}
	return options
}

// Accept 等待一条已独立认证的客户端服务会话。
func (listener *ServiceListener) Accept(ctx context.Context) (p2pnode.Connection, error) {
	select {
	case <-listener.ctx.Done():
		return nil, listener.ctx.Err()
	case <-ctx.Done():
		return nil, ctx.Err()
	case connection := <-listener.accepted:
		if connection == nil {
			return nil, errors.New("natnode: service listener closed")
		}
		return connection, nil
	}
}

func (listener *ServiceListener) Snapshot() ServiceListenerSnapshot {
	listener.mu.Lock()
	relayAddress := listener.addr
	if listener.entry != nil && listener.entry.addr != "" {
		relayAddress = listener.entry.addr
	}
	carrierSessions := make(map[*serviceCarrier]int)
	sessions := make([]ServiceSessionSnapshot, 0, len(listener.active))
	for connectionID, connection := range listener.active {
		peerID := ""
		if connection != nil {
			peerID = string(connection.Peer().ID)
		}
		carrier := listener.sessionCarriers[connectionID]
		carrierSessions[carrier]++
		relay := ""
		if carrier != nil {
			relay = carrier.addr
			if carrier.entry != nil && carrier.entry.addr != "" {
				relay = carrier.entry.addr
			}
		}
		sessions = append(sessions, ServiceSessionSnapshot{ConnectionID: connectionID, PeerID: peerID, RelayAddress: relay})
	}
	carriers := make([]ServiceCarrierSnapshot, 0, len(listener.carriers))
	carrierConnected := false
	for _, carrier := range listener.carriers {
		connected := !listener.closed && carrier.entry != nil && carrier.mux != nil &&
			networkFrameWork.ActiveLegCount(carrier.entry.stream) > 0
		carrierConnected = carrierConnected || connected
		relay := carrier.addr
		if carrier.entry != nil && carrier.entry.addr != "" {
			relay = carrier.entry.addr
		}
		muxSnapshot := networkFrameWork.EndpointFrameMuxSnapshot{}
		if carrier.mux != nil {
			muxSnapshot = carrier.mux.Snapshot()
		}
		carriers = append(carriers, ServiceCarrierSnapshot{
			RelayAddress: relay, Connected: connected, CarrierGeneration: carrier.generation,
			ActiveSessions: carrierSessions[carrier],
			DataQueueDepth: muxSnapshot.DataQueueDepth, DataQueueCapacity: muxSnapshot.DataQueueCapacity,
			ControlQueueDepth: muxSnapshot.ControlQueueDepth, ControlQueueCapacity: muxSnapshot.ControlQueueCapacity,
		})
	}
	listener.mu.Unlock()
	sort.Slice(sessions, func(left, right int) bool {
		return sessions[left].ConnectionID < sessions[right].ConnectionID
	})
	sort.Slice(carriers, func(left, right int) bool {
		return carriers[left].RelayAddress < carriers[right].RelayAddress
	})
	return ServiceListenerSnapshot{
		RelayAddress:      relayAddress,
		CarrierConnected:  carrierConnected,
		CarrierGeneration: listener.carrierSequence.Load(),
		ActiveSessions:    len(sessions),
		MaxSessions:       listener.options.MaxSessions,
		AcceptQueueDepth:  len(listener.accepted),
		AcceptQueue:       cap(listener.accepted),
		AcceptedTotal:     listener.acceptedTotal.Load(),
		RejectedTotal:     listener.rejectedTotal.Load(),
		Carriers:          carriers,
		Sessions:          sessions,
	}
}

// Close 停止新会话、关闭载体并拆除全部活动服务连接，不改变通用 NATNode P2P 生命周期。
func (listener *ServiceListener) Close() error {
	listener.closeOnce.Do(func() {
		listener.cancel()

		listener.mu.Lock()
		listener.closed = true
		carriers := make([]*serviceCarrier, 0, len(listener.carriers))
		for _, carrier := range listener.carriers {
			carriers = append(carriers, carrier)
		}
		active := listener.drainSessionsLocked()
		listener.active = make(map[string]p2pnode.Connection)
		listener.sessionCarriers = make(map[string]*serviceCarrier)
		listener.pending = make(map[string]*serviceCarrier)
		listener.retired = make(map[string]time.Time)
		listener.mu.Unlock()

		for _, carrier := range carriers {
			if carrier.mux != nil {
				carrier.mux.Close()
			}
		}
		for _, connection := range active {
			_ = connection.Close()
			listener.releaseSessionSlot()
		}
		for _, carrier := range carriers {
			if carrier.entry != nil {
				listener.node.removeRegistrationEntry(carrier.entry)
				listener.node.resetBillingControl(carrier.entry.addr)
				_ = carrier.entry.stream.Close()
			}
		}
		listener.workers.Wait()
	})
	return nil
}

func (listener *ServiceListener) maintainCarrier(carrier *serviceCarrier) {
	attempt := 0
	for {
		listener.mu.Lock()
		mux := carrier.mux
		listener.mu.Unlock()
		if mux != nil {
			select {
			case <-listener.ctx.Done():
				return
			case <-listener.node.ctx.Done():
				return
			case <-mux.Done():
			}
			listener.clearCarrier(carrier, mux)
		}
		if listener.ctx.Err() != nil || listener.node.ctx.Err() != nil {
			return
		}

		for retryDelay := 250 * time.Millisecond; listener.ctx.Err() == nil && listener.node.ctx.Err() == nil; {
			timer := time.NewTimer(retryDelay)
			select {
			case <-listener.ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return
			case <-listener.node.ctx.Done():
				if !timer.Stop() {
					<-timer.C
				}
				return
			case <-timer.C:
			}
			attempt++
			if gate, ok := listener.node.transport.(interface {
				WaitForReconnect(context.Context, networkFrameWork.ReconnectGateRequest) error
			}); ok {
				if err := gate.WaitForReconnect(listener.ctx, networkFrameWork.ReconnectGateRequest{
					RelayAddress: carrier.addr,
					Transport:    "carrier",
					NodeID:       string(listener.node.ID()),
					Attempt:      attempt,
					Role:         "natserver",
				}); err != nil {
					return
				}
			}
			if err := listener.openCarrier(carrier); err == nil {
				attempt = 0
				break
			}
			if retryDelay < 5*time.Second {
				retryDelay *= 2
				if retryDelay > 5*time.Second {
					retryDelay = 5 * time.Second
				}
			}
		}
	}
}

func (listener *ServiceListener) openCarrier(carrier *serviceCarrier) error {
	entry, err := listener.node.registerServiceCarrier(carrier.addr, carrier.exact)
	if err != nil {
		return err
	}

	mux, err := networkFrameWork.NewEndpointFrameMux(entry.stream, func(connectionID string, connection net.Conn) {
		listener.acceptVirtualConnection(carrier, connectionID, connection)
	})
	if err != nil {
		listener.node.removeRegistrationEntry(entry)
		listener.node.resetBillingControl(entry.addr)
		_ = entry.stream.Close()
		return fmt.Errorf("natnode: create service endpoint mux: %w", err)
	}

	listener.mu.Lock()
	if listener.closed || listener.ctx.Err() != nil {
		listener.mu.Unlock()
		mux.Close()
		listener.node.removeRegistrationEntry(entry)
		listener.node.resetBillingControl(entry.addr)
		_ = entry.stream.Close()
		return context.Canceled
	}
	carrier.entry = entry
	carrier.mux = mux
	carrier.generation++
	if carrier.addr == listener.addr {
		listener.entry = entry
		listener.mux = mux
	}
	listener.carrierSequence.Add(1)
	listener.mu.Unlock()
	mux.Start()
	return nil
}

func (listener *ServiceListener) clearCarrier(carrier *serviceCarrier, expected *networkFrameWork.EndpointFrameMux) {
	listener.mu.Lock()
	if carrier.mux != expected {
		listener.mu.Unlock()
		return
	}
	entry := carrier.entry
	carrier.entry = nil
	carrier.mux = nil
	if carrier.addr == listener.addr {
		listener.entry = nil
		listener.mux = nil
	}
	active := listener.drainCarrierSessionsLocked(carrier)
	relayAddr := carrier.addr
	generation := carrier.generation
	listener.mu.Unlock()

	logx.Warnf(
		"[billing-trace] stage=service_carrier_clear relay=%s carrierGeneration=%d activeSessions=%d",
		relayAddr, generation, len(active),
	)
	expected.Close()
	for _, connection := range active {
		_ = connection.Close()
		listener.releaseSessionSlot()
	}
	if entry != nil {
		listener.node.removeRegistrationEntry(entry)
		listener.node.resetBillingControl(entry.addr)
		_ = entry.stream.Close()
	}
}

func (listener *ServiceListener) acceptVirtualConnection(carrier *serviceCarrier, connectionID string, rawConnection net.Conn) {
	listener.mu.Lock()
	if listener.closed || listener.ctx.Err() != nil || carrier.mux == nil {
		listener.mu.Unlock()
		_ = rawConnection.Close()
		return
	}
	listener.pruneRetiredLocked(time.Now())
	if expiresAt, retired := listener.retired[connectionID]; retired && time.Now().Before(expiresAt) {
		listener.mu.Unlock()
		listener.rejectedTotal.Add(1)
		listener.closeVirtualConnection(carrier, connectionID, rawConnection)
		return
	}
	if listener.active[connectionID] != nil || listener.pending[connectionID] != nil {
		listener.mu.Unlock()
		listener.rejectedTotal.Add(1)
		listener.closeVirtualConnection(carrier, connectionID, rawConnection)
		return
	}
	select {
	case listener.sessions <- struct{}{}:
		listener.pending[connectionID] = carrier
	default:
		listener.mu.Unlock()
		listener.rejectedTotal.Add(1)
		listener.closeVirtualConnection(carrier, connectionID, rawConnection)
		return
	}
	listener.workers.Add(1)
	listener.mu.Unlock()
	go func() {
		defer listener.workers.Done()
		reserved := true
		defer func() {
			if reserved {
				listener.clearPending(connectionID, carrier)
				listener.releaseSessionSlot()
			}
		}()

		stream := networkFrameWork.NewTCPStream("", connectionID, rawConnection)
		handshakeCtx, cancel := context.WithTimeout(listener.ctx, listener.options.HandshakeTimeout)
		firstMessage, err := stream.NextMessage(handshakeCtx)
		cancel()
		if err != nil || firstMessage == nil || firstMessage.Header == nil {
			listener.rejectedTotal.Add(1)
			listener.closeVirtualConnection(carrier, connectionID, stream)
			return
		}

		peerPublicKey := string(firstMessage.Payload)
		remoteNode, err := DHTable.NewNodeFromPubKeyHex(peerPublicKey)
		if err != nil || !networkFrameWork.SetStreamIdentity(stream, remoteNode.PeerID(), connectionID) {
			listener.rejectedTotal.Add(1)
			listener.closeVirtualConnection(carrier, connectionID, stream)
			return
		}

		streamClient := client.NewStreamClient(stream)
		handshakeCtx, cancel = context.WithTimeout(listener.ctx, listener.options.HandshakeTimeout)
		peerInfo, err := listener.node.handshake.HandshakeIncoming(handshakeCtx, streamClient, firstMessage)
		cancel()
		if err != nil {
			listener.rejectedTotal.Add(1)
			listener.closeVirtualConnection(carrier, connectionID, streamClient)
			return
		}
		if _, err := listener.node.exchangeMetadata(streamClient, peerInfo.ID); err != nil {
			listener.rejectedTotal.Add(1)
			listener.closeVirtualConnection(carrier, connectionID, streamClient)
			return
		}
		stream.StartKeepAlive()

		connection := &serviceConnection{
			Connection: newNATConnection(peerInfo, streamClient, nil, listener.node.billingMeter,
				func() string { return listener.billingRelay(carrier) }, listener.node.resetBillingControl),
			closeFn: func() {
				listener.removeSession(connectionID)
			},
		}

		listener.mu.Lock()
		if listener.closed || listener.ctx.Err() != nil || listener.pending[connectionID] != carrier || carrier.mux == nil {
			listener.mu.Unlock()
			_ = connection.Close()
			return
		}
		delete(listener.pending, connectionID)
		listener.active[connectionID] = connection
		listener.sessionCarriers[connectionID] = carrier
		listener.mu.Unlock()
		reserved = false

		select {
		case listener.accepted <- connection:
			listener.acceptedTotal.Add(1)
		case <-listener.ctx.Done():
			_ = connection.Close()
		default:
			listener.rejectedTotal.Add(1)
			_ = connection.Close()
		}
	}()
}

func (listener *ServiceListener) closeVirtualConnection(carrier *serviceCarrier, connectionID string, connection interface{ Close() error }) {
	listener.mu.Lock()
	mux := carrier.mux
	listener.mu.Unlock()
	if mux != nil {
		mux.CloseConnection(connectionID)
	}
	_ = connection.Close()
}

func (listener *ServiceListener) removeSession(connectionID string) {
	listener.mu.Lock()
	_, exists := listener.active[connectionID]
	delete(listener.active, connectionID)
	carrier := listener.sessionCarriers[connectionID]
	delete(listener.sessionCarriers, connectionID)
	if exists {
		listener.retireConnectionLocked(connectionID, time.Now())
	}
	var mux *networkFrameWork.EndpointFrameMux
	if carrier != nil {
		mux = carrier.mux
	}
	activeSessions := len(listener.active)
	relayAddr := ""
	carrierGeneration := uint64(0)
	if carrier != nil {
		relayAddr = carrier.addr
		carrierGeneration = carrier.generation
	}
	listener.mu.Unlock()
	logx.Debugf(
		"[billing-trace] stage=service_session_removed relay=%s carrierGeneration=%d connId=%s existed=%t activeSessions=%d",
		relayAddr, carrierGeneration, connectionID, exists, activeSessions,
	)
	if mux != nil {
		mux.CloseConnection(connectionID)
	}
	if exists {
		listener.releaseSessionSlot()
	}
}

func (listener *ServiceListener) clearPending(connectionID string, carrier *serviceCarrier) {
	listener.mu.Lock()
	if listener.pending[connectionID] == carrier {
		delete(listener.pending, connectionID)
		listener.retireConnectionLocked(connectionID, time.Now())
	}
	listener.mu.Unlock()
}

func (listener *ServiceListener) billingRelay(carrier *serviceCarrier) string {
	listener.mu.Lock()
	exact := carrier.exact
	relayAddress := carrier.addr
	if carrier.entry != nil && carrier.entry.addr != "" {
		relayAddress = carrier.entry.addr
	}
	listener.mu.Unlock()
	if !exact {
		return listener.node.currentBillingRelay(relayAddress)
	}
	return relayAddress
}

func (listener *ServiceListener) releaseSessionSlot() {
	select {
	case <-listener.sessions:
	default:
	}
}

func (listener *ServiceListener) drainSessionsLocked() []p2pnode.Connection {
	active := make([]p2pnode.Connection, 0, len(listener.active))
	for connectionID, connection := range listener.active {
		active = append(active, connection)
		listener.retireConnectionLocked(connectionID, time.Now())
	}
	listener.active = make(map[string]p2pnode.Connection)
	listener.sessionCarriers = make(map[string]*serviceCarrier)
	return active
}

func (listener *ServiceListener) drainCarrierSessionsLocked(carrier *serviceCarrier) []p2pnode.Connection {
	active := make([]p2pnode.Connection, 0)
	for connectionID, sessionCarrier := range listener.sessionCarriers {
		if sessionCarrier != carrier {
			continue
		}
		if connection := listener.active[connectionID]; connection != nil {
			active = append(active, connection)
		}
		delete(listener.active, connectionID)
		delete(listener.sessionCarriers, connectionID)
		listener.retireConnectionLocked(connectionID, time.Now())
	}
	return active
}

func (listener *ServiceListener) pruneRetiredLocked(now time.Time) {
	for connectionID, expiresAt := range listener.retired {
		if !now.Before(expiresAt) {
			delete(listener.retired, connectionID)
		}
	}
}

func (listener *ServiceListener) retireConnectionLocked(connectionID string, now time.Time) {
	if connectionID == "" {
		return
	}
	if listener.retired == nil {
		listener.retired = make(map[string]time.Time)
	}
	listener.pruneRetiredLocked(now)
	if _, exists := listener.retired[connectionID]; !exists && len(listener.retired) >= serviceConnectionTombstoneLimit {
		var oldestID string
		var oldestExpiry time.Time
		for retiredID, expiresAt := range listener.retired {
			if oldestID == "" || expiresAt.Before(oldestExpiry) {
				oldestID = retiredID
				oldestExpiry = expiresAt
			}
		}
		delete(listener.retired, oldestID)
	}
	listener.retired[connectionID] = now.Add(serviceConnectionTombstoneTTL)
}

func (listener *ServiceListener) closeSessions() {
	listener.mu.Lock()
	active := listener.drainSessionsLocked()
	listener.mu.Unlock()
	for _, connection := range active {
		_ = connection.Close()
		listener.releaseSessionSlot()
	}
}

func (n *NATNode) registerServiceCarrier(addr string, exact bool) (*relayEntry, error) {
	lock := n.registrationLock(addr)
	lock.Lock()
	defer lock.Unlock()

	n.mu.RLock()
	_, exists := n.registeredRelays[addr]
	n.mu.RUnlock()
	if exists {
		return nil, fmt.Errorf("natnode: relay %s already has an active registration", addr)
	}

	var stream network.Stream
	var err error
	if exact {
		registrar, ok := n.transport.(interface {
			RegisterAtRelay(context.Context, string, string) (network.Stream, error)
		})
		if !ok {
			return nil, errors.New("natnode: transport does not support exact Relay registration")
		}
		stream, err = registrar.RegisterAtRelay(n.ctx, addr, n.identity.Pubkey())
	} else {
		stream, err = n.transport.Register(n.ctx, addr, n.identity.Pubkey())
	}
	if err != nil {
		return nil, fmt.Errorf("natnode: service registration to %s failed: %w", addr, err)
	}
	networkFrameWork.EnablePersistentReconnectSurvival(stream)

	entry := &relayEntry{addr: addr, stream: stream, pinned: exact}
	n.mu.Lock()
	if err := n.ctx.Err(); err != nil || n.registeredRelays == nil {
		n.mu.Unlock()
		_ = stream.Close()
		if err == nil {
			err = context.Canceled
		}
		return nil, err
	}
	n.registeredRelays[addr] = entry
	n.entryRelays[addr] = struct{}{}
	n.knownRelays[addr] = struct{}{}
	n.mu.Unlock()

	n.startBillingControl(addr)
	if n.billingMeter.certificate() != nil {
		billingCtx, cancel := context.WithTimeout(n.ctx, 8*time.Second)
		err = n.billingMeter.waitRelaySession(billingCtx, addr, "")
		cancel()
		if err != nil {
			n.removeRegistrationEntry(entry)
			_ = stream.Close()
			n.resetBillingControl(addr)
			return nil, fmt.Errorf("natnode: wait for relay billing session: %w", err)
		}
	}
	return entry, nil
}

// DialService 创建新的 Client/Server 会话，并有意不复用 NATNode 的 P2P 连接缓存。
func (n *NATNode) DialService(ctx context.Context, target p2pnode.NodeID) (p2pnode.Connection, error) {
	targetRelay, err := n.relayFailover.currentTarget()
	if err != nil {
		return nil, fmt.Errorf("natnode: no service relay for %s: %w", target, err)
	}
	rawStream, _, err := n.transport.Dial(ctx, targetRelay.address, target)
	if err != nil {
		return nil, fmt.Errorf("natnode: dial service %s via %s: %w", target, targetRelay.address, err)
	}

	streamClient := client.NewStreamClient(rawStream)
	peerInfo, err := n.handshake.HandshakeOutgoing(ctx, streamClient, target)
	if err != nil {
		_ = streamClient.Close()
		return nil, fmt.Errorf("natnode: service handshake with %s: %w", target, err)
	}
	networkFrameWork.EnableReconnectSurvival(rawStream)
	if _, err := n.exchangeMetadata(streamClient, target); err != nil {
		_ = streamClient.Close()
		return nil, fmt.Errorf("natnode: service metadata exchange with %s: %w", target, err)
	}
	return newNATConnection(peerInfo, streamClient, nil, n.billingMeter,
		func() string { return n.currentBillingRelay(targetRelay.address) }, n.resetBillingControl), nil
}

type serviceConnection struct {
	p2pnode.Connection
	closeOnce sync.Once
	closeFn   func()
}

func (connection *serviceConnection) Close() error {
	var err error
	connection.closeOnce.Do(func() {
		peerID, connectionID := serviceConnectionIdentity(connection.Connection)
		logx.Debugf(
			"[billing-trace] stage=service_connection_close_begin peer=%.16s connId=%s",
			peerID, connectionID,
		)
		err = connection.Connection.Close()
		if connection.closeFn != nil {
			connection.closeFn()
		}
		logx.Debugf(
			"[billing-trace] stage=service_connection_close_done peer=%.16s connId=%s err=%v",
			peerID, connectionID, err,
		)
	})
	return err
}

func (connection *serviceConnection) Send(ctx context.Context, message *p2pnode.Message) error {
	err := connection.Connection.Send(ctx, message)
	if err != nil {
		peerID, connectionID := serviceConnectionIdentity(connection.Connection)
		if isRecoverableServiceSendError(err) {
			logx.Debugf(
				"[billing-trace] stage=service_send_error_recoverable peer=%.16s connId=%s errorType=%T err=%v",
				peerID, connectionID, err, err,
			)
			return err
		}
		logx.Warnf(
			"[billing-trace] stage=service_send_error_close peer=%.16s connId=%s errorType=%T err=%v",
			peerID, connectionID, err, err,
		)
		_ = connection.Close()
	}
	return err
}

func (connection *serviceConnection) Receive(ctx context.Context) (*p2pnode.Message, error) {
	message, err := connection.Connection.Receive(ctx)
	if err != nil {
		peerID, connectionID := serviceConnectionIdentity(connection.Connection)
		logx.Warnf(
			"[billing-trace] stage=service_receive_error_close peer=%.16s connId=%s errorType=%T err=%v",
			peerID, connectionID, err, err,
		)
		_ = connection.Close()
	}
	return message, err
}

func serviceConnectionIdentity(connection p2pnode.Connection) (p2pnode.NodeID, string) {
	if connection == nil {
		return "", ""
	}
	peerID := connection.Peer().ID
	raw := connection.Raw()
	if raw == nil {
		return peerID, ""
	}
	return peerID, raw.ConnectionId()
}
