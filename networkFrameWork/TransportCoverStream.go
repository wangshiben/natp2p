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
// 它必须像裸字节桥接一样【不启动读写循环】(否则 readLoop 会偷走后续 mux 帧),
// 由 onMissingGroup → acceptBridgeMux 直接接管底层裸连接跑 MuxSession。
const relayBridgeMuxRouteHint = "/relay/bridge-mux"

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
	//   clientPubKeyHex 发起方（client）公钥 hex（= 业务首帧 Payload，供 TLS 握手用），
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
			message.Header.RouteName != relayBridgeMuxRouteHint

		// bridge-mux 物理连接握手：与裸字节桥接一样【不启动读写循环】，
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

		if isBridge {
			// 裸字节级跨中继桥接：不启动 readLoop（否则会偷走后续裸字节）。
			//
			// 但**必须**在本地补发首包 ACK：本入口 relay 已经把客户端的首帧（routing-hello,
			// 含公钥）同步读走用于路由, 并改发自己合成的 hello 给对端 relay —— 客户端的这条
			// 首帧根本不会到达真正的 nat 节点, 故端到端 ACK 永远回不来。若不在此本地 ACK,
			// 客户端 recvAckTimer 超时后会重传该首帧, 重传帧经裸字节 splice 透传到 callee,
			// 使 callee 在 TLS 握手里收到**两份公钥**, 错位成 "wrong Salt format"。
			// 跨公网高延迟下必现, 进程内测试因 <1s 完成握手而侥幸不触发。
			// 首帧之后的真实 TLS 负载仍由对端 nat 节点端到端 ACK, 不受影响。
			_ = stream.AckFirstMessage()
			// 直接把 (stream, 首条消息) 交给 handler, handler 会用 stream.RawConn() 做 io.Copy。
			if err := missingHandlerPeek(stream, message); err != nil {
				logx.Errorf("[relay] MissingGroupHandler(桥接) 处理失败: targetNodeId=%.16s connId=%s err=%v",
					message.Header.NodeId, message.Header.ConnectionId, err)
				stream.Close()
				errChan <- err
				return
			}
			errChan <- nil
			return
		}

		// 非桥接路径：补发首包 ACK（readFirstMessageSync 未发）。
		//
		// 注意：StartLoops() 不在此处统一启动，而是推迟到【流模式确定之后】各分支内启动。
		// 原因（修复跨中继握手丢帧竞态）：业务连接 leg 在 StreamOn 里才会被切成 pure-forwarder
		// 并装上 frameTap；若在此处提前 StartLoops，readLoop 可能在模式切换前就读到 client
		// 紧跟首帧发来的下一帧（如 TLS pubkey），把它当普通消息组进【无人读取的死 inbox】，
		// 该帧永不被 frame pump 转发 → 对端握手缺帧卡死。loopback 高速下高频触发，
		// 真机因网络延迟使模式切换先完成而侥幸不现。见记忆 crossrelay-inprocess-hang-rootcause。
		_ = stream.AckFirstMessage()

		if len(message.Header.ConnectionId) == 0 {
			// 注册流：ConnectionId 为空表示这是 relay 注册流。

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
			t.lock.Lock()
			group := t.StreamGroup[stream.NodeId()]
			if group == nil {
				logx.Infof("[relay] 新建 StreamGroup: nodeId=%.16s", stream.NodeId())
				group = NewStreamGroup(stream, defaultHookfunc)
				// 把 TransportCover 上配置的转发 hook 传递给新建的 StreamGroup
				if t.forwardHookConfig != nil {
					group.SetForwardHook(t.forwardHookConfig)
				}
				t.StreamGroup[stream.NodeId()] = group
				registerHook := t.onRegister
				registeredNodeId := stream.NodeId()
				t.lock.Unlock()
				go group.StartListen()
				if registerHook != nil {
					registerHook(registeredNodeId, remoteAddr)
				}
			} else {
				t.lock.Unlock()
				logx.Infof("[relay] 附加 relay leg 到已有 StreamGroup: nodeId=%.16s", stream.NodeId())
				if err := group.AttachRelayStreamCoexist(stream, true); err != nil {
					logx.Errorf("[relay] AttachRelayStream 失败: nodeId=%.16s err=%v", stream.NodeId(), err)
					stream.Close()
					errChan <- err
					return
				}
			}
		} else {
			// 业务连接：ConnectionId 非空表示客户端连接
			t.lock.RLock()
			group := t.StreamGroup[message.Header.NodeId]
			missingHandler := t.onMissingGroup
			businessConnectHook := t.onBusinessConnect
			t.lock.RUnlock()
			if group == nil {
				// 本地没有该目标的 group。若安装了 missing-group 回调（relayNode），
				// 交给它处理：可能是另一台 relay 的控制链路接入，或需要跨中继桥接。
				if missingHandler != nil {
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
			if forwardFirstMessage && isResumeLegMarked(message) {
				forwardFirstMessage = false
				logx.Infof("[relay] 恢复已有 ConnectionId，抑制重复业务首帧: targetNodeId=%.16s connId=%s",
					message.Header.NodeId, message.Header.ConnectionId)
			}
			// 现在 leg 已被 StreamOn 切成 pure-forwarder 并装好 frameTap，再启动读循环：
			// 此后 readLoop 收到的每一帧都进 tap 被 frame pump 可靠转发，不会落入死 inbox。
			stream.StartLoops()
			if forwardFirstMessage {
				if err := group.relayStream.SendMessage(context.Background(), message); err != nil {
					logx.Errorf("[relay] 转发首条消息失败: targetNodeId=%.16s err=%v",
						message.Header.NodeId, err)
					stream.Close()
					errChan <- err
					return
				}
			}
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

func NewTransportCover() *TransportCover {
	return &TransportCover{
		StreamGroup: make(map[string]*StreamGroup),
	}
}
