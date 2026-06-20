package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"errors"
	"fmt"
	"log"
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

	// forwardHookConfig 转发 hook 配置（可选），传递给新创建的 StreamGroup
	forwardHookConfig *ForwardHookConfig
}

// SetMissingGroupHandler 安装「业务连接未命中本地 group」的回调。传 nil 卸载，恢复默认报错行为。
func (t *TransportCover) SetMissingGroupHandler(h func(stream network.Stream, firstMsg *network.Message) error) {
	t.lock.Lock()
	t.onMissingGroup = h
	t.lock.Unlock()
}

// SetRegisterHook 安装「新 relay 注册流建立 group」的回调。传 nil 卸载。
// 回调参数：被托管节点 NodeId、其底层连接远端地址（如 "1.2.3.4:5678"）。
func (t *TransportCover) SetRegisterHook(h func(nodeId, remoteAddr string)) {
	t.lock.Lock()
	t.onRegister = h
	t.lock.Unlock()
}

// SetForwardHook 设置转发 hook 配置，将传递给后续创建的所有 StreamGroup。
// 必须在任何连接建立前调用（通常在 RelayStarter 启动前）。
func (t *TransportCover) SetForwardHook(config *ForwardHookConfig) {
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

func (t *TransportCover) ListenTCPConnection(connection net.Conn) error {
	localAddr := ""
	remoteAddr := ""
	if connection != nil {
		localAddr = connection.LocalAddr().String()
		remoteAddr = connection.RemoteAddr().String()
	}
	log.Printf("[relay] 新连接: local=%s remote=%s", localAddr, remoteAddr)

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
				log.Printf("[relay] panic (local=%s remote=%s): %v", localAddr, remoteAddr, err)
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
			log.Printf("[relay] AcceptTcpStream 失败 (local=%s remote=%s): %v", localAddr, remoteAddr, err)
			connection.Close()
			errChan <- err
			return
		}
		log.Printf("[relay] AcceptTcpStream 成功 (local=%s remote=%s): nodeId=%.16s connId=%s",
			localAddr, remoteAddr, message.Header.NodeId, message.Header.ConnectionId)

		// 预判：是否为「需桥接的业务连接且本地无 group」。
		t.lock.RLock()
		_, hasGroupPeek := t.StreamGroup[message.Header.NodeId]
		missingHandlerPeek := t.onMissingGroup
		t.lock.RUnlock()
		isBridge := len(message.Header.ConnectionId) != 0 && !hasGroupPeek &&
			missingHandlerPeek != nil && message.Header.RouteName != relayControlRouteHint &&
			message.Header.RouteName != relayQueryRouteHint

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
				log.Printf("[relay] MissingGroupHandler(桥接) 处理失败: targetNodeId=%.16s connId=%s err=%v",
					message.Header.NodeId, message.Header.ConnectionId, err)
				stream.Close()
				errChan <- err
				return
			}
			errChan <- nil
			return
		}

		// 非桥接路径：补发首包 ACK（readFirstMessageSync 未发）, 再启动读循环。
		_ = stream.AckFirstMessage()
		stream.StartLoops()

		if len(message.Header.ConnectionId) == 0 {
			// 注册流：ConnectionId 为空表示这是 relay 注册流
			t.lock.Lock()
			group := t.StreamGroup[stream.NodeId()]
			if group == nil {
				log.Printf("[relay] 新建 StreamGroup: nodeId=%.16s", stream.NodeId())
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
				log.Printf("[relay] 附加 relay leg 到已有 StreamGroup: nodeId=%.16s", stream.NodeId())
				if err := group.AttachRelayStream(stream); err != nil {
					log.Printf("[relay] AttachRelayStream 失败: nodeId=%.16s err=%v", stream.NodeId(), err)
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
			t.lock.RUnlock()
			if group == nil {
				// 本地没有该目标的 group。若安装了 missing-group 回调（relayNode），
				// 交给它处理：可能是另一台 relay 的控制链路接入，或需要跨中继桥接。
				if missingHandler != nil {
					if err := missingHandler(stream, message); err != nil {
						log.Printf("[relay] MissingGroupHandler 处理失败: targetNodeId=%.16s connId=%s err=%v",
							message.Header.NodeId, message.Header.ConnectionId, err)
						stream.Close()
						errChan <- err
						return
					}
					// handler 接管了该 stream 的生命周期。
					errChan <- nil
					return
				}
				log.Printf("[relay] StreamGroup 未找到: targetNodeId=%.16s connId=%s",
					message.Header.NodeId, message.Header.ConnectionId)
				stream.Close()
				errChan <- fmt.Errorf("relay group not found for nodeId %s", message.Header.NodeId)
				return
			}
			forwardFirstMessage, err := group.StreamOn(stream, message)
			if err != nil {
				log.Printf("[relay] StreamOn 失败: targetNodeId=%.16s connId=%s err=%v",
					message.Header.NodeId, message.Header.ConnectionId, err)
				stream.Close()
				errChan <- err
				return
			}
			log.Printf("[relay] StreamOn 成功: targetNodeId=%.16s connId=%s forward=%v",
				message.Header.NodeId, message.Header.ConnectionId, forwardFirstMessage)
			if forwardFirstMessage {
				if err := group.relayStream.SendMessage(context.Background(), message); err != nil {
					log.Printf("[relay] 转发首条消息失败: targetNodeId=%.16s err=%v",
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
		log.Printf("[relay] 超时 1 分钟未收到首条消息 (local=%s remote=%s), 关闭连接", localAddr, remoteAddr)
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
