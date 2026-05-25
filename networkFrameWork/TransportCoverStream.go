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

// 目的: 将TCP连接/UDP连接转换成Stream

type TransportCover struct {
	StreamGroup map[string]*StreamGroup // 下一层Stream
	lock        sync.RWMutex
}

func (t *TransportCover) ListenTCPConnection(connection net.Conn) error {
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
				select {
				case errChan <- err:
				default:
					log.Printf("failed to send panic error to channel: %v", err)
				}
				if connection != nil {
					connection.Close()
				}
			}
		}()
		stream, message, err := AcceptTcpStream(connection)
		if err != nil {
			connection.Close()
			errChan <- err
			return
		}
		// 此时是注册为relayStream
		if len(message.Header.ConnectionId) == 0 {
			group := NewStreamGroup(stream, defaultHookfunc)
			t.lock.Lock()
			t.StreamGroup[stream.NodeId()] = group
			t.lock.Unlock()
			go group.StartListen()
		} else {
			t.lock.RLock()
			group := t.StreamGroup[message.Header.NodeId]
			t.lock.RUnlock()
			if group == nil {
				stream.Close()
				errChan <- errors.New("relay group not found for nodeId " + message.Header.NodeId)
				return
			}
			if err := group.StreamOn(stream, message); err != nil {
				stream.Close()
				errChan <- err
				return
			}
			if err := group.relayStream.SendMessage(context.Background(), message); err != nil {
				stream.Close()
				errChan <- err
				return
			}
		}
		errChan <- nil
	}()

	select {
	case <-timeout.Done():
		connection.Close()
		return errors.New("timeout: connection closed")
	case err := <-errChan:
		return err
	}
}

func NewTransportCover() *TransportCover {
	return &TransportCover{
		StreamGroup: make(map[string]*StreamGroup),
		lock:        sync.RWMutex{},
	}
}
