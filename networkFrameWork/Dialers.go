package networkFrameWork

import (
	"bnfs_p2p/logx"
	"bnfs_p2p/network"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/xtaci/kcp-go/v5"
	"net"
	"os"
	"time"
)

const (
	tcpMode              = "tcp"
	udpMode              = "udp"
	dialHandshakeTimeout = 1500 * time.Millisecond
	// kcpPriorityWindow 是客户端拨号时优先等待 KCP leg 完成握手的窗口。
	// 窗口内 KCP 完成则 preferred=KCP(保跨境高吞吐)；超时则用已就绪 TCP 建 preferred，
	// KCP 之后完成仅作 backup。与 relay 侧 kcpWaitWindow 对齐。
	kcpPriorityWindow = 200 * time.Millisecond
)

type RelayDialTarget struct {
	Address    string
	Generation uint64
}

type RelayDialPolicy interface {
	CurrentRelay() (RelayDialTarget, error)
	ReportRelayDialResult(RelayDialTarget, error)
}

type RelayChangeNotifier interface {
	RelayChangeSignal() <-chan struct{}
}

// disableKCP 返回是否显式禁用 KCP leg（走纯双 TCP failover）。
// 场景：家庭 NAT / 运营商限制 UDP，KCP 回程不可靠，relay 优先用 KCP 建桥反而导致
// 端到端握手在丢包的 KCP leg 上失败。设 BNFS_DISABLE_KCP=1 强制 TCP-only。
func disableKCP() bool {
	switch os.Getenv("BNFS_DISABLE_KCP") {
	case "1", "true", "TRUE", "yes":
		return true
	}
	return false
}

// TryConnectTCPStream 客户端主动连指定 relay 并把首条消息送出去，
// 拿到一个已绑定 targetNodeId / connectionId 的逻辑流。
//
// 行为：
//   - 生成一个新的 uuid 作为 connectionId；
//   - 默认走 dual（KCP+TCP 同时拨号，任一成功即返回）；
//   - 首条消息的 Header 用调用方传入的 targetNodeId 标识对端身份，
//     Payload 是发起方自己的 hex 公钥，供对端推导 NodeId。
func TryConnectTCPStream(addr, targetNodeId, originalPubkeyHex string) (network.Stream, string, error) {
	return TryConnectTCPStreamWithConnID(addr, targetNodeId, originalPubkeyHex, uuid.New().String())
}

func TryConnectTCPStreamWithRelayPolicy(policy RelayDialPolicy, targetNodeId, originalPubkeyHex string) (network.Stream, string, error) {
	connectionId := uuid.New().String()
	header := &network.Header{
		NodeId:        targetNodeId,
		NodeIdVersion: 1,
		ConnectionId:  connectionId,
	}
	body := &network.Message{Header: header, Payload: []byte(originalPubkeyHex)}
	stream, err := clientStreamWithRelayPolicy(body, "", targetNodeId, connectionId, true, policy)
	return stream, connectionId, err
}

// TryConnectTCPStreamWithConnID 与 TryConnectTCPStream 相同, 但使用调用方指定的 connectionId
// 而不是新生成一个。
//
// relayNode 跨中继转发时必须用它：把 local1 的原始 connectionId 一路透传到对端 relay,
// 使端到端 connectionId 在 local1↔local2 之间保持一致。否则 relay1 另起新 connId 会让
// 对端节点用不同 connId 应答, 破坏帧路由表 / E2E messageId 去重的一致性。
func TryConnectTCPStreamWithConnID(addr, targetNodeId, originalPubkeyHex, connectionId string) (network.Stream, string, error) {
	header := &network.Header{
		RouteName:     "",
		NodeId:        targetNodeId,
		NodeIdVersion: 1,
		PayLoadLength: 0,
		ConnectionId:  connectionId,
		OriginData:    nil,
	}
	body := &network.Message{
		Header:  header,
		Payload: []byte(originalPubkeyHex),
	}
	stream, err := clientStream(body, addr, targetNodeId, connectionId, true)
	return stream, connectionId, err
}

// TryConnectControlStream 建立一条「带 RouteName 标记」的业务连接。
//
// 与 TryConnectTCPStream 唯一的区别是首条 hello 消息的 Header.RouteName 由调用方指定，
// 而不是固定为空。relayNode 用它建立 relay→relay 控制链路：把 routeName 设为
// RelayControlRoute，对端 relay 在 MissingGroupHandler 里据此识别"这是控制链路接入，
// 而不是普通客户端要连接某个本地未托管的 nat 节点"。
//
// 行为与 TryConnectTCPStream 一致：dual 拨号 + 自动重连 dialer，
// 首条消息 Payload 为发起方公钥 hex，供对端推导 NodeId。
func TryConnectControlStream(addr, targetNodeId, originalPubkeyHex, routeName string) (network.Stream, string, error) {
	connectionId := uuid.New().String()
	header := &network.Header{
		RouteName:     routeName,
		NodeId:        targetNodeId,
		NodeIdVersion: 1,
		PayLoadLength: 0,
		ConnectionId:  connectionId,
		OriginData:    nil,
	}
	body := &network.Message{
		Header:  header,
		Payload: []byte(originalPubkeyHex),
	}
	stream, err := clientStream(body, addr, targetNodeId, connectionId, true)
	return stream, connectionId, err
}

// TryConnectControlStreamTCP 与 TryConnectControlStream 相同, 但只用单条 TCP leg(不走 dual KCP+TCP)。
//
// 用于一次性请求/应答(如 natnode 向 index 查询 relay 列表): dual 拨号会对同一 connId 产生
// KCP+TCP 两条 leg, 两条都会带着同一首帧(hello/公钥)进入对端的 MissingGroupHandler, 一次性
// 处理器只应答并关闭其中一条, 另一条 leg 残留并把重复首帧投递下去 —— 在跨中继桥接路径上这会让
// 对端把同一公钥帧收两次, 端到端 TLS 握手错位(salt 处读到公钥)。单 TCP leg 彻底规避该竞态。
func TryConnectControlStreamTCP(addr, targetNodeId, originalPubkeyHex, routeName string) (network.Stream, string, error) {
	connectionId := uuid.New().String()
	header := &network.Header{
		RouteName:     routeName,
		NodeId:        targetNodeId,
		NodeIdVersion: 1,
		ConnectionId:  connectionId,
	}
	body := &network.Message{
		Header:  header,
		Payload: []byte(originalPubkeyHex),
	}
	stream, err := clientStream(body, addr, targetNodeId, connectionId, false)
	return stream, connectionId, err
}

// TryRegisterRelayStream 把本节点注册成一条可被中继的「relay 注册流」。
// 此时 ConnectionId 为空，意味着这条流不绑业务连接，专门接受其他客户端通过它中转。
// originalNodeId 由 pubKey 哈希派生，对端用它做身份校验。
func TryRegisterRelayStream(pubKey, relayAddress string) (network.Stream, error) {
	hash := sha256.Sum256([]byte(pubKey))
	originalNodeId := hex.EncodeToString(hash[:])

	header := &network.Header{
		RouteName:     "",
		NodeId:        originalNodeId,
		NodeIdVersion: 1,
		PayLoadLength: 0,
		ConnectionId:  "",
		LegSessionId:  uuid.New().String(),
		OriginData:    nil,
	}
	body := &network.Message{
		Header:  header,
		Payload: []byte(pubKey),
	}
	return clientStream(body, relayAddress, originalNodeId, "", true)
}

// TryRegisterRelayStreamWithSign 与 TryRegisterRelayStream 相同, 但在注册消息 payload 里
// 携带 CA 签发的 indexSign(admission.SignedCert JSON)——网络准入用。
//
// 关键: originalNodeId 仍由【裸公钥】哈希派生(与不带证书时一致), 只有 payload 换成信封
// {pk, is}。接收侧 TransportCover 用 DecodeRegisterPayload 取回内部 pk、以 SHA256(pk) 修正
// 真实 nodeId, 故 group key 不变、路由不受影响。signJSON 为空时退化为裸公钥(等价旧函数)。
func TryRegisterRelayStreamWithSign(pubKey, relayAddress string, signJSON []byte) (network.Stream, error) {
	hash := sha256.Sum256([]byte(pubKey))
	originalNodeId := hex.EncodeToString(hash[:])
	header := &network.Header{
		RouteName:     "",
		NodeId:        originalNodeId,
		NodeIdVersion: 1,
		ConnectionId:  "",
		LegSessionId:  uuid.New().String(),
	}
	body := &network.Message{
		Header:  header,
		Payload: EncodeRegisterPayload(pubKey, signJSON),
	}
	return clientStream(body, relayAddress, originalNodeId, "", true)
}

func TryRegisterRelayStreamWithSignAndRelayPolicy(pubKey string, signJSON []byte, policy RelayDialPolicy) (network.Stream, error) {
	hash := sha256.Sum256([]byte(pubKey))
	originalNodeId := hex.EncodeToString(hash[:])
	header := &network.Header{
		NodeId:        originalNodeId,
		NodeIdVersion: 1,
		ConnectionId:  "",
		LegSessionId:  uuid.New().String(),
	}
	body := &network.Message{Header: header, Payload: EncodeRegisterPayload(pubKey, signJSON)}
	return clientStreamWithRelayPolicy(body, "", originalNodeId, "", true, policy)
}

// TryRegisterRelayStreamTCP 与 TryRegisterRelayStream 相同, 但只用单条 TCP leg 注册（不走 dual KCP+TCP）。
// 用于跨中继场景下避免 relayStream 的 KCP/TCP 双 leg 在中继转发处的 failover 竞态。
func TryRegisterRelayStreamTCP(pubKey, relayAddress string) (network.Stream, error) {
	hash := sha256.Sum256([]byte(pubKey))
	originalNodeId := hex.EncodeToString(hash[:])
	header := &network.Header{
		RouteName:     "",
		NodeId:        originalNodeId,
		NodeIdVersion: 1,
		ConnectionId:  "",
		LegSessionId:  uuid.New().String(),
	}
	body := &network.Message{Header: header, Payload: []byte(pubKey)}
	return clientStream(body, relayAddress, originalNodeId, "", false)
}

// TryConnectTCPOnlyStream 与 TryConnectTCPStream 相同, 但只用单条 TCP leg 连接（不走 dual）。
// 用于跨中继：源节点单 leg 连入口 relay, 入口 relay 单 leg 桥接, 全链路 TCP 单 leg, 无 failover 竞态。
func TryConnectTCPOnlyStream(addr, targetNodeId, originalPubkeyHex string) (network.Stream, string, error) {
	connectionId := uuid.New().String()
	header := &network.Header{
		RouteName:     "",
		NodeId:        targetNodeId,
		NodeIdVersion: 1,
		ConnectionId:  connectionId,
	}
	body := &network.Message{Header: header, Payload: []byte(originalPubkeyHex)}
	stream, err := clientStream(body, addr, targetNodeId, connectionId, false)
	return stream, connectionId, err
}

// TryRegisterStream : nat后设备注册Stream
// 参数:
//
//	addr: 要连接的中转服务器地址
//	originalPubkeyHex: 自己的公钥
//	streamMode: 可选: tcp/udp，默认udp，若无法连接，则使用tcp
//	targetNodeId: 目标节点的nodeId(如果不是短时连接某一特定节点，则此项可不填)
//
// 返回值:
//
//	network.Stream: 流对象
//	string: 流的connectionId(当targetNodeId不为空时有)
//	error: 错误信息
func TryRegisterStream(addr, originalPubkeyHex, targetNodeId, streamMode string) (network.Stream, string, error) {
	hash := sha256.Sum256([]byte(originalPubkeyHex))
	originalNodeId := hex.EncodeToString(hash[:])
	connectionId := ""
	if len(targetNodeId) != 0 {
		connectionId = uuid.New().String()
	}
	header := &network.Header{
		RouteName:     "",
		NodeId:        originalNodeId,
		NodeIdVersion: 1,
		PayLoadLength: 0,
		ConnectionId:  connectionId,
		OriginData:    nil,
	}
	if connectionId == "" {
		header.LegSessionId = uuid.New().String()
	}
	body := &network.Message{
		Header:  header,
		Payload: []byte(originalPubkeyHex),
	}
	if streamMode == udpMode {
		stream, err := clientStream(body, addr, originalNodeId, connectionId, true)
		if err != nil {
			return nil, "", err
		}
		return stream, connectionId, nil
	} else if streamMode == tcpMode {
		stream, err := clientStream(body, addr, originalNodeId, connectionId, false)
		if err != nil {
			return nil, "", err
		}
		return stream, connectionId, nil
	}
	return nil, "", errors.New("wrong stream mode")
}

// clientStream 是底层拨号入口。
//
//	isDefault=false：仅 TCP，单 leg；
//	isDefault=true ：dual 模式，KCP+TCP 同时拨号，任一成功即返回；
//	                 同时为两种协议分别注入重连 dialer，后续 leg 失效会自动重拨。
func clientStream(FirstMessage *network.Message, tcpAddr, originalNodeId, connectionId string, isDefault bool) (network.Stream, error) {
	return clientStreamWithRelayPolicy(FirstMessage, tcpAddr, originalNodeId, connectionId, isDefault, nil)
}

func clientStreamWithRelayPolicy(FirstMessage *network.Message, tcpAddr, originalNodeId, connectionId string, isDefault bool, relayPolicy RelayDialPolicy) (network.Stream, error) {
	if !isDefault {
		return tcpClientStream(FirstMessage, tcpAddr, originalNodeId, connectionId)
	}

	dual := newDualStream(originalNodeId, connectionId)
	dual.beginInitialDialSetup()
	if notifier, ok := relayPolicy.(RelayChangeNotifier); ok {
		dual.watchRelayChanges(notifier)
	}
	template := cloneMessage(FirstMessage)
	var kcpErr error
	var tcpErr error
	dialTCP := func(ctx context.Context, message *network.Message) (network.Stream, error) {
		if relayPolicy == nil {
			return tcpClientStreamContext(ctx, message, tcpAddr, originalNodeId, connectionId, true)
		}
		target, err := relayPolicy.CurrentRelay()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRelayCandidatesExhausted, err)
		}
		stream, dialErr := tcpClientStreamContext(ctx, message, target.Address, originalNodeId, connectionId, true)
		relayPolicy.ReportRelayDialResult(target, dialErr)
		return stream, dialErr
	}
	dialKCP := func(ctx context.Context, message *network.Message) (network.Stream, error) {
		if relayPolicy == nil {
			return kcpStreamContext(ctx, message, tcpAddr, originalNodeId, connectionId, true)
		}
		target, err := relayPolicy.CurrentRelay()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrRelayCandidatesExhausted, err)
		}
		stream, dialErr := kcpStreamContext(ctx, message, target.Address, originalNodeId, connectionId, true)
		// KCP 失败只能说明 UDP 路径不可用，不能据此把 TCP 正常的 Relay 判死。
		// Relay 候选推进只由 TCP 失败驱动；KCP 成功仍可清零该地址的失败计数。
		if dialErr == nil {
			relayPolicy.ReportRelayDialResult(target, nil)
		}
		return stream, dialErr
	}

	// dual 模式：所有 leg 都不自发心跳(noKeepAlive=true)，改由 DualStream 统一只在
	// 当前 preferred leg 上发心跳（见 startKeepAlive）。原因：relay 跨中继桥接按「最近发字节的
	// leg」决定回程 active leg；若 standby leg 也自发心跳，会把 active 翻到 standby，下一段
	// peer→local 下行数据就被错路由到 standby，在 32KB 读边界处把一帧劈成两半 → 两条 leg 同时
	// 解析失败 → 重连风暴。让心跳只走 preferred、standby 全程静默，active 就稳定在数据 leg 上；
	// 主 leg 死后 failover 切换 preferred，心跳与 active 一起迁移，天然 role-swap 安全。
	tcpDialer := func(ctx context.Context) (network.Stream, error) {
		message := cloneMessage(template)
		markResumeLeg(message)
		return dialTCP(ctx, message)
	}
	kcpDialer := func(ctx context.Context) (network.Stream, error) {
		message := cloneMessage(template)
		markResumeLeg(message)
		return dialKCP(ctx, message)
	}
	// extraTCPDialer 用于"双 TCP failover 的第二条 TCP"：首帧打 legExtraMarker 标记，
	// 让 relay 端把它当作并存 leg（而非顶替已有同协议 leg）。同样不自发心跳。
	extraTCPDialer := func(ctx context.Context) (network.Stream, error) {
		fm := cloneMessage(template)
		markExtraLeg(fm)
		markResumeLeg(fm)
		return dialTCP(ctx, fm)
	}
	setInitialReconnectDialer := func(id streamTransport, dialer streamReconnectDialer, persistent bool) {
		if persistent {
			dual.setPersistentReconnectDialer(id, dialer)
			return
		}
		dual.SetReconnectDialer(id, dialer)
	}
	kcpDisabled := disableKCP()
	if !kcpDisabled {
		setInitialReconnectDialer(streamTransportKCP, kcpDialer, false)
	}
	setInitialReconnectDialer(streamTransportTCP, tcpDialer, relayPolicy != nil)

	// KCP 优先 + 200ms 窗口：KCP 与 TCP 并发拨号(各自发首帧、等端到端 ACK)。偏向 KCP：
	//   - KCP 在 kcpPriorityWindow(200ms) 内完成握手 → preferred=KCP(保跨境高吞吐)；
	//   - 窗口内 KCP 未完成(家庭 NAT UDP 回程不通等) → 用已就绪的 TCP 建 preferred，
	//     KCP 之后若完成则作 backup failover leg 补入(不抢 preferred)。
	// 用「有界并发」而非串行先拨 KCP 再拨 TCP：200ms 后 TCP 可以先成为 preferred，
	// 但本函数仍等待 KCP 在 1500ms 握手期限内给出最终结果，才能决定并入 KCP 还是补第二条 TCP。
	type dialResult struct {
		kind   streamTransport
		stream network.Stream
		err    error
	}
	resCh := make(chan dialResult, 2)
	// kcpCtx 只用于显式禁用和函数退出时清理。200ms 优先窗口只决定 preferred，不能取消
	// 仍在完整握手期限内推进的 KCP；否则真实 WAN 上 200ms 后才完成的健康 KCP 会被错误吞掉，
	// dual 随后退化成双 TCP，与“晚到 KCP 作为 backup 并入”的设计相矛盾。
	kcpCtx, kcpCancel := context.WithCancel(context.Background())
	defer kcpCancel()
	if kcpDisabled {
		kcpCancel()
		resCh <- dialResult{streamTransportKCP, nil, fmt.Errorf("KCP disabled by BNFS_DISABLE_KCP")}
	} else {
		go func() {
			s, e := dialKCP(kcpCtx, cloneMessage(template))
			resCh <- dialResult{streamTransportKCP, s, e}
		}()
	}
	go func() {
		s, e := dialTCP(context.Background(), cloneMessage(template))
		resCh <- dialResult{streamTransportTCP, s, e}
	}()

	kcpOK := false
	tcpOK := false
	attach := func(r dialResult) {
		if r.err != nil {
			if r.kind == streamTransportKCP {
				kcpErr = r.err
			} else {
				tcpErr = r.err
			}
			return
		}
		legID := r.kind
		aerr := dual.attachWithID(legID, r.kind, r.stream)
		if aerr != nil {
			_ = r.stream.Close()
			if r.kind == streamTransportKCP {
				kcpErr = aerr
			} else {
				tcpErr = aerr
			}
			return
		}
		if r.kind == streamTransportKCP {
			kcpOK = true
		} else {
			tcpOK = true
		}
	}

	// 优先等 KCP 最多 kcpPriorityWindow；期间先到的 TCP 暂存，让 KCP 有机会先成 preferred。
	received := 0
	var tcpPending *dialResult
	kcpWindowOpen := true
	timer := time.NewTimer(kcpPriorityWindow)
	for received < 2 {
		if kcpWindowOpen {
			select {
			case r := <-resCh:
				received++
				if r.kind == streamTransportKCP {
					attach(r) // KCP 有结果：成功则成 preferred；无论成败都结束优先窗口
					kcpWindowOpen = false
					if tcpPending != nil {
						attach(*tcpPending)
						tcpPending = nil
					}
				} else {
					rr := r
					tcpPending = &rr // TCP 先到，暂存继续等 KCP
				}
			case <-timer.C:
				// 200ms 到，KCP 未定：已就绪 TCP 成为 preferred；KCP 继续使用自己的
				// dialHandshakeTimeout，若随后成功则作为 backup attach，实现 KCP/TCP 共存。
				kcpWindowOpen = false
				if tcpPending != nil {
					attach(*tcpPending)
					tcpPending = nil
				}
			}
		} else {
			r := <-resCh
			received++
			attach(r)
		}
	}
	timer.Stop()

	// KCP 失败但已有 TCP：补一条 extra TCP leg 保「双 TCP failover」冗余。
	// extra 首帧带 legExtraMarker，relay 据此并存而非顶替已有同协议 leg。
	if !kcpOK && tcpOK {
		// 初始 KCP 已明确失败，不能让完成握手后的 reconnect survival 再用 Resume
		// 复活这条从未建立过的 leg。即使 extra TCP 首拨失败，冗余恢复也只由
		// tcp#2 的独立重连拨号器负责。
		dual.SetReconnectDialer(streamTransportKCP, nil)
		extraLegID := relayBackupLegID(streamTransportTCP)
		setInitialReconnectDialer(extraLegID, extraTCPDialer, relayPolicy != nil)
		extraFirst := cloneMessage(FirstMessage)
		markExtraLeg(extraFirst)
		if tcp2, e2 := dialTCP(context.Background(), extraFirst); e2 == nil {
			if aerr := dual.attachWithID(extraLegID, streamTransportTCP, tcp2); aerr != nil {
				_ = tcp2.Close()
			} else {
				logx.Infof("[Dialers] KCP 不通, 补第二条 TCP leg(id=%s) 组成双 TCP failover: target=%.16s connId=%s",
					extraLegID, originalNodeId, connectionId)
			}
		} else {
			tcpErr = e2
		}
	}

	if !dual.finishInitialDialSetup() {
		if tcpErr != nil {
			return nil, tcpErr
		}
		if kcpErr != nil {
			return nil, kcpErr
		}
		return nil, errors.New("all initial dual-stream legs closed during setup")
	}
	// 统一心跳：只在 preferred leg 上发，standby 静默（见上方注释）。
	dual.startKeepAlive()
	return dual, nil
}

func tcpClientStream(FirstMessage *network.Message, tcpAddr, originalNodeId, connectionId string) (network.Stream, error) {
	return tcpClientStreamContext(context.Background(), FirstMessage, tcpAddr, originalNodeId, connectionId)
}

// tcpClientStreamContext 拨一条 TCP leg。可选 noKeepAlive=true 时不启动 keepLive 心跳，
// 用于「双 TCP failover 的第二条 TCP」——它在 relay 桥接里是 silent standby:
// 不发心跳 → relay 桥接的 active leg 不会被它的心跳往返翻动 → 下行数据不会被错路由到它、
// 不会在 32KB 读边界处把一帧劈成两半造成两条 leg 同时损坏。主 leg 死后客户端 sendOrder
// 自然切到它，届时它才开始发数据、成为 active。
func tcpClientStreamContext(ctx context.Context, FirstMessage *network.Message, tcpAddr, originalNodeId, connectionId string, noKeepAlive ...bool) (network.Stream, error) {
	handshakeCtx, cancel := context.WithTimeout(ctx, dialHandshakeTimeout)
	defer cancel()

	var dialer net.Dialer
	conn, err := dialer.DialContext(handshakeCtx, "tcp4", tcpAddr)
	if err != nil {
		return nil, err
	}

	// TCP 优化：禁用 Nagle 算法，设置缓冲区
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetReadBuffer(2 * 1024 * 1024)
		_ = tcpConn.SetWriteBuffer(2 * 1024 * 1024)
	}

	res := startTcpStream(originalNodeId, connectionId, conn)
	if err := res.SendMessage(handshakeCtx, cloneMessage(FirstMessage)); err != nil {
		res.Close()
		return nil, err
	}
	if !(len(noKeepAlive) > 0 && noKeepAlive[0]) {
		go res.keepLive()
	}
	return res, nil
}

func kcpStream(FirstMessage *network.Message, tcpAddr, originalNodeId, connectionId string) (network.Stream, error) {
	return kcpStreamContext(context.Background(), FirstMessage, tcpAddr, originalNodeId, connectionId)
}

func kcpStreamContext(ctx context.Context, FirstMessage *network.Message, tcpAddr, originalNodeId, connectionId string, noKeepAlive ...bool) (network.Stream, error) {
	handshakeCtx, cancel := context.WithTimeout(ctx, dialHandshakeTimeout)
	defer cancel()

	conn, err := kcp.DialWithOptions(tcpAddr, nil, 1, 1)
	if err != nil {
		return nil, err
	}
	// 调优 KCP 参数以提升吞吐：
	// - interval 从 50ms 降到 10ms，提升响应速度
	// - MTU 从 1000 提升到 1400（安全的互联网 MTU）
	// - 窗口从 128/512 提升到 256/1024，容纳更多在途数据
	conn.SetNoDelay(1, 10, 2, 1)
	conn.SetMtu(1400)
	conn.SetWriteBuffer(4 * 1024 * 1024)
	conn.SetWindowSize(256, 1024)

	res := startTcpStream(originalNodeId, connectionId, conn)
	if err := res.SendMessage(handshakeCtx, cloneMessage(FirstMessage)); err != nil {
		res.Close()
		return nil, err
	}
	// dual 模式下心跳由 DualStream 统一只在 preferred leg 上发（见 clientStream 注释），
	// 各 leg 不再自发心跳；noKeepAlive=true 即此用途。单 leg 路径保持各自心跳。
	if !(len(noKeepAlive) > 0 && noKeepAlive[0]) {
		go res.keepLive()
	}
	return res, nil
}
