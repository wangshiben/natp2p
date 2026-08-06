package networkFrameWork

import (
	"bnfs_p2p/logx"
	"bnfs_p2p/network"
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// relayControlRouteHint 与 relaynode.RelayControlRoute 取值一致（此处不便导入 relaynode 包,
// 否则循环依赖）。用于在 TransportCover 层区分「控制链路接入」与「需桥接的业务连接」。
const relayControlRouteHint = "/relay/control"

// relayQueryRouteHint 与 relaynode.RelayQueryRoute 取值一致（同样为避免循环依赖, 用常量副本,
// 由注释保持同步）。natnode 向 index 拉取 relay 列表的一次性请求/应答走此 RouteName。
// 它与控制链路一样必须排除出「桥接」判定: 桥接分支不启动读写循环, 而查询应答需要在同一条
// stream 上正常 SendMessage/NextMessage（先 AckFirstMessage + StartLoops）。
const relayQueryRouteHint = "/relay/query"

// relayBridgeMuxRouteHint 与 relaynode.RelayBridgeMuxRoute 取值一致（避免循环依赖, 常量副本,
// 由注释保持同步）。relay↔relay 多路复用桥接物理连接的握手 RouteName。
// 它必须在握手分支保持【不启动读写循环】（否则 readLoop 会偷走后续 mux 帧），
// 由 onMissingGroup → acceptBridgeMux 直接接管底层裸连接跑 MuxSession。
const relayBridgeMuxRouteHint = "/relay/bridge-mux"

// billingControlRouteHint 是 NAT 与其入口 Relay 的链路本地双签控制流。
// 即使目标 NodeID 已有托管 StreamGroup，也必须由 MissingGroupHandler 直接接管，不能送进业务流。
const billingControlRouteHint = "/billing/control/v1"

const (
	retiredRegistrationSessionTTL   = 10 * time.Minute
	retiredRegistrationSessionLimit = 32
	retiredBusinessConnectionTTL    = 10 * time.Minute
	retiredBusinessConnectionLimit  = 4096
	dormantRegistrationSessionLimit = 4096
	defaultRegistrationIdleTimeout  = 90 * time.Second
	defaultRegistrationSweepPeriod  = 5 * time.Second
)

var ErrStaleRegistrationSession = errors.New("stale registration session")

var ErrStaleBusinessConnection = errors.New("business connection belongs to a retired registration session")

type retiredBusinessConnection struct {
	registrationSessionID string
	expiresAt             time.Time
}

type dormantRegistrationSession struct {
	registrationSessionID             string
	connectionIDs                     []string
	initializationFailedConnectionIDs []string
	expiresAt                         time.Time
}

// TransportCover 将 TCP/UDP 连接转换为 Stream。
type TransportCover struct {
	StreamGroup map[string]*StreamGroup
	lock        sync.RWMutex

	// onMissingGroup 在「业务连接寻址的目标 NodeId 在本地没有对应 StreamGroup」时被调用。
	// relayNode 用它实现两类逻辑：
	//   - FirstMessage.Header.RouteName == RelayControlRoute：这是另一台 relay 发来的控制链路接入，
	//     交给 relayNode 的控制处理器跑 TLS + FIND 协议；
	//   - 否则：本地未托管该 nat 节点，relayNode 向邻近 relay 查找并跨中继桥接。
	// 返回 nil 表示已接管该 stream（handler 拥有其生命周期）；返回非 nil 表示处理失败。
	// 为 nil 时保持原行为：直接关闭 stream 并报 "relay group not found"。
	onMissingGroup func(stream network.Stream, firstMsg *network.Message) error

	// onRegister 在新的 relay 注册流（ConnectionId 为空）首次建立 StreamGroup 时被调用，
	// 参数是该被托管节点的 NodeId 及其底层连接的远端地址（用于排障 / 展示托管来源 IP）。
	// relayNode 用它把本地托管的 nat 节点登记进 natNodes DHT 并记录来源地址。
	onRegister func(nodeId, remoteAddr string)

	// onUnregister 只在当前 StreamGroup 被 compare-delete 确认退出后调用。
	// 回调与注册回调由 registrationLifecycle 串行化，但绝不在 TransportCover 主锁内执行；
	// 这样既保持旧代注销先于新代注册的顺序，也避免控制面广播阻塞所有业务连接。
	onUnregister func(nodeId string)

	// onRegisterVerify 是可选的「注册准入校验」钩子，在【建 StreamGroup 之前】被调用。
	// 参数：被托管节点 NodeId、注册消息里携带的 indexSign(admission.SignedCert JSON, 可空)、
	// 底层远端地址。返回非 nil error 表示拒绝该注册（框架关闭流、不建 group）。
	// 为 nil（默认）时不做任何校验，行为与旧版一致。relayNode 用它做无交互 indexSign 离线验签 + 落角色。
	onRegisterVerify func(nodeId string, signJSON []byte, remoteAddr string) error

	// onBusinessConnect 是可选的「业务连接接入校验」钩子，在业务连接被路由到某个【本地已托管】
	// 目标节点、且【StreamOn 之前】被调用。返回非 nil error 表示拒绝该业务连接（框架关闭流）。
	// 为 nil（默认）时不做任何校验，行为与旧版一致。
	//
	// 参数：
	//   targetNodeId    被连接/被服务的目标（server）NodeId（= 业务首帧 Header.NodeId）。
	//   clientPubKeyHex 发起方（client）公钥 hex（= 业务首帧 Payload，供 Noise 身份绑定使用），
	//                   relayNode 据它派生 client NodeId。
	//   connID          本次业务连接标识。
	//
	// relayNode 用它实现两件事：
	//   1) 方案B 服务边界角色强制——只有 role=server 的被托管节点才能作为业务连接目标被服务；
	//   2) 连接保证金——建连时对 client/server 各扣一笔入场费（经 CA /reserve），任一方不足即拒。
	// 二者都在此点一次性完成（每条业务连接首帧触发一次）。
	onBusinessConnect func(targetNodeId, clientPubKeyHex, connID string) error

	// forwardHookConfig 转发 hook 配置（可选），传递给新创建的 StreamGroup
	forwardHookConfig *ForwardHookConfig

	retiredRegistrationSessions map[string]map[string]time.Time
	retiredBusinessConnections  map[string]map[string]retiredBusinessConnection
	dormantRegistrationSessions map[string]dormantRegistrationSession

	registrationIdleTimeout time.Duration
	registrationSweepPeriod time.Duration
	idleSweeperRunning      bool
	registrationLifecycle   sync.Mutex
}

// SetBusinessConnectHook 安装「业务连接接入校验」钩子（StreamOn 前调用，返回 error 则拒绝接入）。传 nil 卸载。
func (t *TransportCover) SetBusinessConnectHook(h func(targetNodeId, clientPubKeyHex, connID string) error) {
	t.lock.Lock()
	t.onBusinessConnect = h
	t.lock.Unlock()
}

// SetRegisterVerifyHook 安装「注册准入校验」钩子（建 group 前调用，返回 error 则拒绝注册）。传 nil 卸载。
func (t *TransportCover) SetRegisterVerifyHook(h func(nodeId string, signJSON []byte, remoteAddr string) error) {
	t.lock.Lock()
	t.onRegisterVerify = h
	t.lock.Unlock()
}

// SetMissingGroupHandler 安装「业务连接未命中本地 group」的回调。传 nil 卸载，恢复默认报错行为。
func (t *TransportCover) SetMissingGroupHandler(h func(stream network.Stream, firstMsg *network.Message) error) {
	t.lock.Lock()
	t.onMissingGroup = h
	t.lock.Unlock()
}

// SetRegisterHook 安装「新 relay 注册流建立 group」的回调。传 nil 卸载。
// 回调参数：被托管节点 NodeId、其底层连接远端地址（如 "203.0.113.10:5678"）。
func (t *TransportCover) SetRegisterHook(h func(nodeId, remoteAddr string)) {
	t.lock.Lock()
	t.onRegister = h
	t.lock.Unlock()
}

// SetUnregisterHook 安装当前注册组退出后的回调。传 nil 卸载。
// 回调不得调用同一个 TransportCover 的方法。
func (t *TransportCover) SetUnregisterHook(h func(nodeId string)) {
	t.lock.Lock()
	t.onUnregister = h
	t.lock.Unlock()
}

// SetRegistrationIdlePolicy 配置注册组的被动静默回收策略。
// 应在接收连接前调用；idleTimeout <= 0 表示禁用，sweepPeriod <= 0 使用默认扫描周期。
func (t *TransportCover) SetRegistrationIdlePolicy(idleTimeout, sweepPeriod time.Duration) {
	t.lock.Lock()
	t.registrationIdleTimeout = idleTimeout
	if sweepPeriod <= 0 {
		sweepPeriod = defaultRegistrationSweepPeriod
	}
	t.registrationSweepPeriod = sweepPeriod
	if idleTimeout > 0 && len(t.StreamGroup) > 0 {
		t.ensureIdleSweeperLocked()
	}
	t.lock.Unlock()
}

// SetForwardHook 设置转发 hook 配置，将传递给后续创建的所有 StreamGroup。
// 必须在任何连接建立前调用（通常在 RelayStarter 启动前）。
func (t *TransportCover) SetForwardHook(config *ForwardHookConfig) {
	if config != nil {
		config.ensureRetransmitCache()
	}
	t.lock.Lock()
	t.forwardHookConfig = config
	t.lock.Unlock()
}

// HasGroup 报告某个 NodeId 当前是否在本 relay 上有对应的 StreamGroup（即被本地托管）。
func (t *TransportCover) HasGroup(nodeId string) bool {
	t.lock.RLock()
	_, ok := t.StreamGroup[nodeId]
	t.lock.RUnlock()
	return ok
}

// CloseHostedConnection 关闭挂在某被托管节点(nodeId)的 group 下的一条业务连接(connID)。
//
// 用于「连接终止 server 也能参与」：托管 server B 的 relay 据 (B 的 nodeId, connID) 拆掉
// 对应 client leg（复用 StreamGroup.CloseTargetConnection：删除映射 + 关闭底层 stream +
// 取消 ctx，pump/loop 立即退出）。找不到 group / 连接返回 error。
func (t *TransportCover) CloseHostedConnection(nodeId, connID string) error {
	t.lock.RLock()
	group := t.StreamGroup[nodeId]
	t.lock.RUnlock()
	if group == nil {
		return fmt.Errorf("relay: 未托管 nodeId=%.16s, 无法终止连接", nodeId)
	}
	return group.CloseTargetConnection(connID)
}

func (t *TransportCover) ListenTCPConnection(connection net.Conn) error {
	localAddr := ""
	remoteAddr := ""
	if connection != nil {
		localAddr = connection.LocalAddr().String()
		remoteAddr = connection.RemoteAddr().String()
	}
	logx.Infof("[relay] 新连接: local=%s remote=%s", localAddr, remoteAddr)

	// TCP 优化：服务端接受连接后立即设置 NoDelay 和缓冲区
	if tcpConn, ok := connection.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetReadBuffer(2 * 1024 * 1024)
		_ = tcpConn.SetWriteBuffer(2 * 1024 * 1024)
	}

	timeout, cancelFunc := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancelFunc()
	errChan := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				var err error
				switch v := r.(type) {
				case error:
					err = v
				case string:
					err = fmt.Errorf("panic: %s", v)
				default:
					err = fmt.Errorf("panic: %v", v)
				}
				logx.Errorf("[relay] panic (local=%s remote=%s): %v", localAddr, remoteAddr, err)
				select {
				case errChan <- err:
				default:
				}
				if connection != nil {
					connection.Close()
				}
			}
		}()
		stream, message, err := AcceptTcpStreamSync(connection)
		if err != nil {
			logx.Errorf("[relay] AcceptTcpStream 失败 (local=%s remote=%s): %v", localAddr, remoteAddr, err)
			connection.Close()
			errChan <- err
			return
		}
		logx.Infof("[relay] AcceptTcpStream 成功 (local=%s remote=%s): nodeId=%.16s connId=%s",
			localAddr, remoteAddr, message.Header.NodeId, message.Header.ConnectionId)

		// 预判：是否为「需桥接的业务连接且本地无 group」。
		t.lock.RLock()
		_, hasGroupPeek := t.StreamGroup[message.Header.NodeId]
		missingHandlerPeek := t.onMissingGroup
		t.lock.RUnlock()
		isBridge := len(message.Header.ConnectionId) != 0 && !hasGroupPeek &&
			missingHandlerPeek != nil && message.Header.RouteName != relayControlRouteHint &&
			message.Header.RouteName != relayQueryRouteHint &&
			message.Header.RouteName != relayBridgeMuxRouteHint &&
			message.Header.RouteName != billingControlRouteHint

		// bridge-mux 物理连接握手：【不启动读写循环】，
		// 直接把底层裸连接交给 handler(acceptBridgeMux) 跑 MuxSession。
		if message.Header.RouteName == relayBridgeMuxRouteHint && missingHandlerPeek != nil {
			_ = stream.AckFirstMessage()
			if err := missingHandlerPeek(stream, message); err != nil {
				logx.Errorf("[relay] MissingGroupHandler(bridge-mux) 处理失败: peer=%.16s err=%v",
					message.Header.NodeId, err)
				stream.Close()
				errChan <- err
				return
			}
			errChan <- nil
			return
		}

		if message.Header.RouteName == billingControlRouteHint && missingHandlerPeek != nil {
			if err := stream.AckFirstMessage(); err != nil {
				_ = stream.Close()
				errChan <- err
				return
			}
			stream.StartLoops()
			go runBillingControlHandler(stream, message, missingHandlerPeek)
			errChan <- nil
			return
		}

		if isBridge {
			// 逐帧跨中继桥接：先由 handler 安装 pure-forwarder/frame tap，再启动 readLoop。
			//
			// 成功建桥后**必须**在本地补发首包 ACK：本入口 relay 已经把客户端的首帧（routing-hello,
			// 含公钥）同步读走用于路由, 并改发自己合成的 hello 给对端 relay —— 客户端的这条
			// 首帧根本不会到达真正的 nat 节点, 故端到端 ACK 永远回不来。若不在此本地 ACK,
			// 客户端 recvAckTimer 超时后会重传该首帧；若把这份路由 hello 当业务帧继续转发，
			// callee 会在 TLS 握手里收到**两份公钥**，错位成 "wrong Salt format"。
			// 跨公网高延迟下必现, 进程内测试因 <1s 完成握手而侥幸不触发。
			// 首帧之后的真实 TLS 负载仍由对端 nat 节点端到端 ACK, 不受影响。
			// ACK 不能早于 handler 成功：目标尚未注册时提前确认会让发起端把一次失败桥接
			// 当成成功重连，Relay 随即关闭连接，形成无退避的重连/EOF 活锁。
			// 把 (stream, 首条消息) 交给 handler；handler 会先完成逐帧桥接配置再启动循环。
			if err := missingHandlerPeek(stream, message); err != nil {
				logx.Errorf("[relay] MissingGroupHandler(桥接) 处理失败: targetNodeId=%.16s connId=%s err=%v",
					message.Header.NodeId, message.Header.ConnectionId, err)
				stream.Close()
				errChan <- err
				return
			}
			if err := stream.AckFirstMessage(); err != nil {
				stream.Close()
				errChan <- err
				return
			}
			errChan <- nil
			return
		}

		// 非桥接路径由各分支在完成必要的首帧处理后补发 ACK 并启动循环。
		//
		// 注意：AckFirstMessage() / StartLoops() 不在此处统一执行，而是推迟到
		// 【流模式和首帧去向确定之后】各分支内执行。
		// 原因（修复跨中继握手丢帧竞态）：业务连接 leg 在 StreamOn 里才会被切成 pure-forwarder
		// 并装上 frameTap；若在此处提前 StartLoops，readLoop 可能在模式切换前就读到 client
		// 紧跟首帧发来的下一帧（如 TLS pubkey），把它当普通消息组进【无人读取的死 inbox】，
		// 该帧永不被 frame pump 转发 → 对端握手缺帧卡死。loopback 高速下高频触发，
		// 真机因网络延迟使模式切换先完成而侥幸不现。见记忆 crossrelay-inprocess-hang-rootcause。

		if len(message.Header.ConnectionId) == 0 {
			// 注册流：ConnectionId 为空表示这是 relay 注册流。
			// 注册代次切换与注销回调共用一把独立生命周期锁。它不能是 TransportCover
			// 主锁：RelayNode 的 onRegister/onUnregister 会广播托管路由，慢控制链路可能
			// 阻塞数秒；若广播期间持有主锁，所有业务 StreamOn 都会形成全局 HOL。
			t.registrationLifecycle.Lock()
			defer t.registrationLifecycle.Unlock()
			_ = stream.AckFirstMessage()

			// 网络准入(indexSign): 注册 payload 可能是「裸公钥 hex」(旧/无证书)或「JSON 信封
			// {pk,is}」(带 CA 证书)。信封情况下 SHA256(payload) != SHA256(pk)，需按内部 pk 修正
			// 真实 nodeId(作为 group key)。裸公钥情况下 realNodeId == stream.NodeId()，为无操作。
			pubKeyHex, signJSON := DecodeRegisterPayload(message.Payload)
			realNodeId := NodeIDFromPubKeyHex(pubKeyHex)
			if realNodeId != stream.NodeId() {
				SetStreamIdentity(stream, realNodeId, message.Header.ConnectionId)
			}
			// 准入校验钩子（建 group 之前）：验签失败/角色不符则拒绝注册。为 nil 时不校验。
			t.lock.RLock()
			verify := t.onRegisterVerify
			t.lock.RUnlock()
			if verify != nil {
				if err := verify(realNodeId, signJSON, remoteAddr); err != nil {
					logx.Errorf("[relay] 注册准入校验失败, 拒绝: nodeId=%.16s remote=%s err=%v", realNodeId, remoteAddr, err)
					stream.Close()
					errChan <- err
					return
				}
			}

			// 注册流不切 pure-forwarder（它就是被 StreamGroup 用 Message 语义消费/转发的载体），
			// 故可立即启动读循环。
			stream.StartLoops()
			registrationSessionID := message.Header.LegSessionId
			resume := isResumeLegMarked(message)
			extra := isExtraLegMarked(message)
			var retiredGroup *StreamGroup
			var inheritedConnectionIDs []string
			var inheritedInitializationFailedConnectionIDs []string
			var registerHook func(nodeId, remoteAddr string)
			var registeredNodeId string
			now := time.Now()
			t.lock.Lock()
			group := t.StreamGroup[stream.NodeId()]
			if t.isRegistrationSessionRetiredLocked(stream.NodeId(), registrationSessionID, now) {
				t.lock.Unlock()
				err := fmt.Errorf("%w: nodeId=%.16s session=%s",
					ErrStaleRegistrationSession, stream.NodeId(), registrationSessionID)
				logx.Warnf("[relay] 拒绝已退役注册代次: %v", err)
				stream.Close()
				errChan <- err
				return
			}
			if group != nil && group.isClosed() {
				if registrationSessionChanged(group.registrationSessionID, registrationSessionID) {
					t.retireGroupLocked(stream.NodeId(), group, now)
					retiredGroup = group
				} else {
					inheritedConnectionIDs = append(inheritedConnectionIDs, group.snapshotConnectionIDs()...)
					inheritedInitializationFailedConnectionIDs = append(inheritedInitializationFailedConnectionIDs,
						group.snapshotInitializationFailedConnectionIDs()...)
				}
				delete(t.StreamGroup, stream.NodeId())
				group = nil
			}
			if group != nil && registrationSessionChanged(group.registrationSessionID, registrationSessionID) {
				if resume {
					t.lock.Unlock()
					err := fmt.Errorf("%w: nodeId=%.16s active=%s incoming=%s",
						ErrStaleRegistrationSession, stream.NodeId(), group.registrationSessionID, registrationSessionID)
					logx.Warnf("[relay] 拒绝旧代次 Resume 注册: %v", err)
					stream.Close()
					errChan <- err
					return
				}
				t.retireGroupLocked(stream.NodeId(), group, now)
				retiredGroup = group
				group = nil
			}
			if group == nil {
				if dormant, ok := t.takeDormantRegistrationSessionLocked(stream.NodeId(), now); ok {
					if registrationSessionChanged(dormant.registrationSessionID, registrationSessionID) {
						t.retireRegistrationSessionLocked(stream.NodeId(), dormant.registrationSessionID, now)
						t.retireBusinessConnectionsLocked(stream.NodeId(), dormant.registrationSessionID,
							dormant.connectionIDs, now)
					} else {
						inheritedConnectionIDs = append(inheritedConnectionIDs, dormant.connectionIDs...)
						inheritedInitializationFailedConnectionIDs = append(inheritedInitializationFailedConnectionIDs,
							dormant.initializationFailedConnectionIDs...)
					}
				}
				group = newStreamGroupWithRelaySession(stream, defaultHookfunc, extra, registrationSessionID)
				group.inheritConnectionIDs(inheritedConnectionIDs)
				group.inheritInitializationFailedConnectionIDs(inheritedInitializationFailedConnectionIDs)
				// 把 TransportCover 上配置的转发 hook 传递给新建的 StreamGroup
				if t.forwardHookConfig != nil {
					group.SetForwardHook(t.forwardHookConfig)
				}
				t.StreamGroup[stream.NodeId()] = group
				t.ensureIdleSweeperLocked()
				registerHook = t.onRegister
				registeredNodeId = stream.NodeId()
				t.lock.Unlock()
				go t.listenGroup(stream.NodeId(), group)
				if retiredGroup != nil {
					retiredGroup.Close()
					logx.Infof("[relay] 注册代次切换并清理旧 StreamGroup: nodeId=%.16s old=%s new=%s",
						registeredNodeId, retiredGroup.registrationSessionID, registrationSessionID)
				}
				if registerHook != nil {
					registerHook(registeredNodeId, remoteAddr)
				}
				logx.Infof("[relay] 新建 StreamGroup: nodeId=%.16s session=%s", registeredNodeId, registrationSessionID)
			} else {
				t.lock.Unlock()
				if err := group.attachRelayStreamCoexist(stream, extra, resume); err != nil {
					logx.Errorf("[relay] AttachRelayStream 失败: nodeId=%.16s err=%v", stream.NodeId(), err)
					stream.Close()
					errChan <- err
					return
				}
				logx.Infof("[relay] 附加 relay leg 到已有 StreamGroup: nodeId=%.16s", stream.NodeId())
			}
		} else {
			// 业务连接：ConnectionId 非空表示客户端连接
			t.lock.Lock()
			group := t.StreamGroup[message.Header.NodeId]
			missingHandler := t.onMissingGroup
			businessConnectHook := t.onBusinessConnect
			staleBusinessConnection := group != nil &&
				t.isBusinessConnectionRetiredLocked(message.Header.NodeId, message.Header.ConnectionId,
					group.registrationSessionID, time.Now())
			t.lock.Unlock()
			if group == nil {
				// 本地没有该目标的 group。若安装了 missing-group 回调（relayNode），
				// 交给它处理：可能是另一台 relay 的控制链路接入，或需要跨中继桥接。
				if missingHandler != nil {
					_ = stream.AckFirstMessage()
					// 控制链路 / relay 查询等：handler 会在该流上正常 NextMessage/SendMessage,
					// 需先启动读循环。（桥接业务连接已在上方 isBridge 分支提前接管，不会到这里。）
					stream.StartLoops()
					if err := missingHandler(stream, message); err != nil {
						logx.Errorf("[relay] MissingGroupHandler 处理失败: targetNodeId=%.16s connId=%s err=%v",
							message.Header.NodeId, message.Header.ConnectionId, err)
						stream.Close()
						errChan <- err
						return
					}
					// handler 接管了该 stream 的生命周期。
					errChan <- nil
					return
				}
				logx.Errorf("[relay] StreamGroup 未找到: targetNodeId=%.16s connId=%s",
					message.Header.NodeId, message.Header.ConnectionId)
				stream.Close()
				errChan <- fmt.Errorf("relay group not found for nodeId %s", message.Header.NodeId)
				return
			}
			if staleBusinessConnection {
				err := fmt.Errorf("%w: targetNodeId=%.16s connId=%s",
					ErrStaleBusinessConnection, message.Header.NodeId, message.Header.ConnectionId)
				logx.Warnf("[relay] 拒绝旧服务端代次的业务 leg: %v", err)
				stream.Close()
				errChan <- err
				return
			}
			// 服务边界角色强制（方案B）：本地托管该目标节点, 在把业务连接接上它之前校验其角色。
			// relayNode 用它拒绝「非 server 角色的节点作为被连接的目标」——即堵死「client 节点
			// 提供服务却逃计费」的路径。为 nil（默认/准入关闭）时不校验, 行为与旧版一致。
			if businessConnectHook != nil {
				if err := businessConnectHook(message.Header.NodeId, string(message.Payload), message.Header.ConnectionId); err != nil {
					logx.Errorf("[relay] 业务连接被拒(角色/保证金): targetNodeId=%.16s connId=%s err=%v",
						message.Header.NodeId, message.Header.ConnectionId, err)
					stream.Close()
					errChan <- err
					return
				}
			}
			forwardFirstMessage, err := group.StreamOn(stream, message)
			if err != nil {
				logx.Errorf("[relay] StreamOn 失败: targetNodeId=%.16s connId=%s err=%v",
					message.Header.NodeId, message.Header.ConnectionId, err)
				stream.Close()
				errChan <- err
				return
			}
			logx.Infof("[relay] StreamOn 成功: targetNodeId=%.16s connId=%s forward=%v",
				message.Header.NodeId, message.Header.ConnectionId, forwardFirstMessage)
			if err := group.AwaitFirstMessage(message.Header.ConnectionId); err != nil {
				logx.Errorf("[relay] 等待服务端确认业务首帧失败: targetNodeId=%.16s err=%v",
					message.Header.NodeId, err)
				stream.Close()
				errChan <- err
				return
			}
			// 新逻辑连接只有在目标 Server 的真实 ACK 返回后才确认原始首帧；同代 Resume
			// 则等待同一个 shared gate 后本地确认。先 ACK 再开读循环，使等待期间积压的
			// 首帧重传由 TcpStream 去重，不会被 frame pump 当成第二份公钥继续转发。
			if err := stream.AckFirstMessage(); err != nil {
				stream.Close()
				errChan <- err
				return
			}
			stream.StartLoops()
		}
		errChan <- nil
	}()

	select {
	case <-timeout.Done():
		logx.Errorf("[relay] 超时 1 分钟未收到首条消息 (local=%s remote=%s), 关闭连接", localAddr, remoteAddr)
		connection.Close()
		return errors.New("timeout: connection closed")
	case err := <-errChan:
		return err
	}
}

func runBillingControlHandler(
	stream network.Stream,
	firstMessage *network.Message,
	handler func(network.Stream, *network.Message) error,
) {
	defer func() {
		if recovered := recover(); recovered != nil {
			logx.Errorf("[relay] MissingGroupHandler(billing-control) panic: peer=%.16s panic=%v",
				stream.NodeId(), recovered)
			_ = stream.Close()
		}
	}()
	if err := handler(stream, firstMessage); err != nil {
		logx.Errorf("[relay] MissingGroupHandler(billing-control) 处理失败: peer=%.16s err=%v",
			stream.NodeId(), err)
		_ = stream.Close()
	}
}

func (t *TransportCover) listenGroup(nodeID string, group *StreamGroup) {
	t.lock.Lock()
	t.ensureIdleSweeperLocked()
	t.lock.Unlock()
	group.StartListen()

	// 与新注册串行化 compare-delete 和生命周期回调，但回调必须在主锁外执行。
	// 新注册若先取得此锁，会原子替换旧 group，下面 compare-delete 随即跳过；
	// 注销若先取得此锁，则先完整发布离线事件，新注册随后再发布上线事件。
	t.registrationLifecycle.Lock()
	defer t.registrationLifecycle.Unlock()
	var unregisterHook func(string)
	t.lock.Lock()
	if t.StreamGroup[nodeID] == group {
		delete(t.StreamGroup, nodeID)
		t.rememberDormantRegistrationSessionLocked(nodeID, group, time.Now())
		unregisterHook = t.onUnregister
	}
	t.lock.Unlock()
	if unregisterHook != nil {
		unregisterHook(nodeID)
	}
}

func (t *TransportCover) ensureIdleSweeperLocked() {
	if t.idleSweeperRunning || t.registrationIdleTimeout <= 0 || len(t.StreamGroup) == 0 {
		return
	}
	t.idleSweeperRunning = true
	period := t.registrationSweepPeriod
	if period <= 0 {
		period = defaultRegistrationSweepPeriod
	}
	go t.runIdleSweeper(period)
}

func (t *TransportCover) runIdleSweeper(period time.Duration) {
	ticker := time.NewTicker(period)
	defer ticker.Stop()
	for now := range ticker.C {
		t.lock.Lock()
		if len(t.StreamGroup) == 0 || t.registrationIdleTimeout <= 0 {
			t.idleSweeperRunning = false
			t.lock.Unlock()
			return
		}
		timeout := t.registrationIdleTimeout
		groups := make(map[string]*StreamGroup, len(t.StreamGroup))
		for nodeID, group := range t.StreamGroup {
			groups[nodeID] = group
		}
		t.lock.Unlock()

		cutoff := now.Add(-timeout)
		for nodeID, group := range groups {
			lastReceive := group.latestRelayReceiveTime()
			if lastReceive.IsZero() || lastReceive.After(cutoff) {
				continue
			}
			// 在真正关闭前重新读取，避免扫描快照之后刚附加或刚恢复活跃的 leg 被误杀。
			lastReceive = group.latestRelayReceiveTime()
			if lastReceive.IsZero() || lastReceive.After(time.Now().Add(-timeout)) {
				continue
			}
			// Receive silence is a congestion/quality signal, not proof of death.
			// In particular a busy KCP scheduler can starve the preferred leg while
			// a connected TCP backup remains immediately usable. The endpoint
			// heartbeat now promotes that backup; only reap after all carriers have
			// actually closed so a valid long-idle registration is never destroyed.
			if group.relayCarrierStale(timeout) {
				logx.Warnf("[relay] 回收收帧已停止的注册 StreamGroup: nodeId=%.16s idle=%s timeout=%s",
					nodeID, time.Since(lastReceive).Round(time.Second), timeout)
				group.Close()
				continue
			}
			if group.hasLiveRelayCarrier() {
				continue
			}
			logx.Warnf("[relay] 回收已无存活 carrier 的静默注册 StreamGroup: nodeId=%.16s idle=%s timeout=%s",
				nodeID, time.Since(lastReceive).Round(time.Second), timeout)
			group.Close()
		}
	}
}

func registrationSessionChanged(currentSessionID, incomingSessionID string) bool {
	return incomingSessionID != "" && currentSessionID != incomingSessionID
}

func (t *TransportCover) rememberDormantRegistrationSessionLocked(nodeID string, group *StreamGroup, now time.Time) {
	if nodeID == "" || group == nil {
		return
	}
	if t.dormantRegistrationSessions == nil {
		t.dormantRegistrationSessions = make(map[string]dormantRegistrationSession)
	}
	for dormantNodeID, dormant := range t.dormantRegistrationSessions {
		if !now.Before(dormant.expiresAt) {
			delete(t.dormantRegistrationSessions, dormantNodeID)
		}
	}
	if _, exists := t.dormantRegistrationSessions[nodeID]; !exists &&
		len(t.dormantRegistrationSessions) >= dormantRegistrationSessionLimit {
		var oldestNodeID string
		var oldestExpiry time.Time
		for dormantNodeID, dormant := range t.dormantRegistrationSessions {
			if oldestNodeID == "" || dormant.expiresAt.Before(oldestExpiry) {
				oldestNodeID = dormantNodeID
				oldestExpiry = dormant.expiresAt
			}
		}
		delete(t.dormantRegistrationSessions, oldestNodeID)
	}
	t.dormantRegistrationSessions[nodeID] = dormantRegistrationSession{
		registrationSessionID:             group.registrationSessionID,
		connectionIDs:                     group.snapshotConnectionIDs(),
		initializationFailedConnectionIDs: group.snapshotInitializationFailedConnectionIDs(),
		expiresAt:                         now.Add(retiredRegistrationSessionTTL),
	}
}

func (t *TransportCover) takeDormantRegistrationSessionLocked(nodeID string, now time.Time) (dormantRegistrationSession, bool) {
	dormant, ok := t.dormantRegistrationSessions[nodeID]
	if !ok {
		return dormantRegistrationSession{}, false
	}
	delete(t.dormantRegistrationSessions, nodeID)
	if !now.Before(dormant.expiresAt) {
		return dormantRegistrationSession{}, false
	}
	return dormant, true
}

func (t *TransportCover) retireGroupLocked(nodeID string, group *StreamGroup, now time.Time) {
	if group == nil {
		return
	}
	connectionIDs := group.stopAndSnapshotConnectionIDs()
	t.retireRegistrationSessionLocked(nodeID, group.registrationSessionID, now)
	t.retireBusinessConnectionsLocked(nodeID, group.registrationSessionID, connectionIDs, now)
}

func (t *TransportCover) retireRegistrationSessionLocked(nodeID, sessionID string, now time.Time) {
	if nodeID == "" || sessionID == "" {
		return
	}
	sessions := t.retiredRegistrationSessions[nodeID]
	if sessions == nil {
		sessions = make(map[string]time.Time)
		t.retiredRegistrationSessions[nodeID] = sessions
	}
	for id, expiresAt := range sessions {
		if !now.Before(expiresAt) {
			delete(sessions, id)
		}
	}
	for len(sessions) >= retiredRegistrationSessionLimit {
		var oldestID string
		var oldestExpiry time.Time
		for id, expiresAt := range sessions {
			if oldestID == "" || expiresAt.Before(oldestExpiry) {
				oldestID = id
				oldestExpiry = expiresAt
			}
		}
		delete(sessions, oldestID)
	}
	sessions[sessionID] = now.Add(retiredRegistrationSessionTTL)
}

func (t *TransportCover) isRegistrationSessionRetiredLocked(nodeID, sessionID string, now time.Time) bool {
	if nodeID == "" || sessionID == "" {
		return false
	}
	sessions := t.retiredRegistrationSessions[nodeID]
	if sessions == nil {
		return false
	}
	for id, expiresAt := range sessions {
		if !now.Before(expiresAt) {
			delete(sessions, id)
		}
	}
	if len(sessions) == 0 {
		delete(t.retiredRegistrationSessions, nodeID)
		return false
	}
	_, ok := sessions[sessionID]
	return ok
}

func (t *TransportCover) retireBusinessConnectionsLocked(nodeID, sessionID string, connectionIDs []string, now time.Time) {
	if nodeID == "" || sessionID == "" || len(connectionIDs) == 0 {
		return
	}
	connections := t.retiredBusinessConnections[nodeID]
	if connections == nil {
		connections = make(map[string]retiredBusinessConnection)
		t.retiredBusinessConnections[nodeID] = connections
	}
	for connectionID, retired := range connections {
		if !now.Before(retired.expiresAt) {
			delete(connections, connectionID)
		}
	}
	for _, connectionID := range connectionIDs {
		if connectionID == "" {
			continue
		}
		if len(connections) >= retiredBusinessConnectionLimit {
			var oldestID string
			var oldestExpiry time.Time
			for id, retired := range connections {
				if oldestID == "" || retired.expiresAt.Before(oldestExpiry) {
					oldestID = id
					oldestExpiry = retired.expiresAt
				}
			}
			delete(connections, oldestID)
		}
		connections[connectionID] = retiredBusinessConnection{
			registrationSessionID: sessionID,
			expiresAt:             now.Add(retiredBusinessConnectionTTL),
		}
	}
}

func (t *TransportCover) isBusinessConnectionRetiredLocked(nodeID, connectionID, activeSessionID string, now time.Time) bool {
	if nodeID == "" || connectionID == "" || activeSessionID == "" {
		return false
	}
	connections := t.retiredBusinessConnections[nodeID]
	if connections == nil {
		return false
	}
	retired, ok := connections[connectionID]
	if !ok {
		return false
	}
	if !now.Before(retired.expiresAt) {
		delete(connections, connectionID)
		if len(connections) == 0 {
			delete(t.retiredBusinessConnections, nodeID)
		}
		return false
	}
	return retired.registrationSessionID != activeSessionID
}

func NewTransportCover() *TransportCover {
	return &TransportCover{
		StreamGroup:                 make(map[string]*StreamGroup),
		retiredRegistrationSessions: make(map[string]map[string]time.Time),
		retiredBusinessConnections:  make(map[string]map[string]retiredBusinessConnection),
		dormantRegistrationSessions: make(map[string]dormantRegistrationSession),
		registrationIdleTimeout:     defaultRegistrationIdleTimeout,
		registrationSweepPeriod:     defaultRegistrationSweepPeriod,
	}
}
