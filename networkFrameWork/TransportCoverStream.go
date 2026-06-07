package networkFrameWork

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// TransportCover 将 TCP/UDP 连接转换为 Stream。
type TransportCover struct {
	StreamGroup map[string]*StreamGroup
	lock        sync.RWMutex
}

func (t *TransportCover) ListenTCPConnection(connection net.Conn) error {
	localAddr := ""
	remoteAddr := ""
	if connection != nil {
		localAddr = connection.LocalAddr().String()
		remoteAddr = connection.RemoteAddr().String()
	}
	log.Printf("[relay] 新连接: local=%s remote=%s", localAddr, remoteAddr)

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
		stream, message, err := AcceptTcpStream(connection)
		if err != nil {
			log.Printf("[relay] AcceptTcpStream 失败 (local=%s remote=%s): %v", localAddr, remoteAddr, err)
			connection.Close()
			errChan <- err
			return
		}
		log.Printf("[relay] AcceptTcpStream 成功 (local=%s remote=%s): nodeId=%.16s connId=%s",
			localAddr, remoteAddr, message.Header.NodeId, message.Header.ConnectionId)

		if len(message.Header.ConnectionId) == 0 {
			// 注册流：ConnectionId 为空表示这是 relay 注册流
			t.lock.Lock()
			group := t.StreamGroup[stream.NodeId()]
			if group == nil {
				log.Printf("[relay] 新建 StreamGroup: nodeId=%.16s", stream.NodeId())
				group = NewStreamGroup(stream, defaultHookfunc)
				t.StreamGroup[stream.NodeId()] = group
				t.lock.Unlock()
				go group.StartListen()
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
			t.lock.RUnlock()
			if group == nil {
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
