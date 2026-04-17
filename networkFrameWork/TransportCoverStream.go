package networkFrameWork

import (
	"context"
	"errors"
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
	errChan := make(chan error)
	go func() {
		message, err := tryReadMessageFromConnection(connection)
		if err != nil {
			connection.Close()
			errChan <- err
		}
		stream, err := TrySetupRelayStream(connection, message)
		if err != nil {
			connection.Close()
			errChan <- err
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
			stream.SendMessage(context.Background(), message)
			if group != nil {
				err := group.StreamOn(stream, message)
				if err != nil {
					stream.Close()
					errChan <- err
				}
			}
			t.lock.RUnlock()
		}
		errChan <- nil
	}()

	select {
	case <-timeout.Done():

		connection.Close()
		return errors.New("timeout: connection closed")

	case err := <-errChan:
		if err != nil {
			return err
		}
		return nil
	}

}

func NewTransportCover() *TransportCover {
	return &TransportCover{
		StreamGroup: make(map[string]*StreamGroup),
		lock:        sync.RWMutex{},
	}
}
