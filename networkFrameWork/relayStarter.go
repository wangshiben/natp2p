package networkFrameWork

import (
	"bnfs_p2p/logx"
	"errors"
	"fmt"
	"github.com/xtaci/kcp-go/v5"
	"net"
	"sync"
)

const relayHandshakeConcurrency = 128

var ErrRelayStarterClosed = errors.New("relay starter closed before startup completed")

func dispatchRelayConnection(protocol string, connection net.Conn, slots chan struct{}, handler func(net.Conn) error) bool {
	select {
	case slots <- struct{}{}:
	default:
		logx.Warnf("[relay] %s 握手并发已满，拒绝新连接: remote=%s limit=%d",
			protocol, connection.RemoteAddr(), cap(slots))
		_ = connection.Close()
		return false
	}

	go func() {
		defer func() { <-slots }()
		if err := handler(connection); err != nil {
			logx.Errorf("[relay] Listen%sConnection error: %v", protocol, err)
		}
	}()
	return true
}

// RelayStarter 中转服务启动器(公网服务器特有)
type RelayStarter struct {
	addr        string // 监听地址
	netGroup    *TransportCover
	closeSignal chan struct{}
	ready       chan struct{}
	done        chan struct{}

	startOnce sync.Once
	closeOnce sync.Once
	readyOnce sync.Once
	doneOnce  sync.Once

	lifecycleMu sync.RWMutex
	startCalled bool
	startErr    error
}

func (r *RelayStarter) StartListen() {
	r.startOnce.Do(r.startListen)
}

func (r *RelayStarter) startListen() {
	r.lifecycleMu.Lock()
	r.startCalled = true
	r.lifecycleMu.Unlock()
	defer r.doneOnce.Do(func() { close(r.done) })

	if r.isClosing() {
		r.setStartError(ErrRelayStarterClosed)
		return
	}
	tcpListener, err := net.Listen("tcp", r.addr)
	if err != nil {
		r.setStartError(fmt.Errorf("relay starter listen TCP %s: %w", r.addr, err))
		return
	}
	defer tcpListener.Close()
	if r.isClosing() {
		r.setStartError(ErrRelayStarterClosed)
		return
	}
	// 1. 通过密码和盐生成密钥
	//key := pbkdf2.Key([]byte("wangshibenbens"), []byte("your_salt"), 1024, 32, sha1.New)
	//crypt, err := kcp.NewAESBlockCrypt(key)
	//if err != nil {
	//	panic(err)
	//	return
	//}
	kcplistener, err := kcp.ListenWithOptions(r.addr, nil, 1, 1)
	if err != nil {
		r.setStartError(fmt.Errorf("relay starter listen KCP %s: %w", r.addr, err))
		return
	}
	defer kcplistener.Close()
	if r.isClosing() {
		r.setStartError(ErrRelayStarterClosed)
		return
	}
	tcpHandshakeSlots := make(chan struct{}, relayHandshakeConcurrency)
	kcpHandshakeSlots := make(chan struct{}, relayHandshakeConcurrency)
	go func() {
		for {
			tcpConn, err := tcpListener.Accept()
			if err != nil {
				return
			}
			if tcpConn == nil {
				continue
			}
			dispatchRelayConnection("TCP", tcpConn, tcpHandshakeSlots, r.netGroup.ListenTCPConnection)
		}
	}()
	go func() {
		for {
			kcpConn, err := kcplistener.Accept()
			if err != nil {
				return
			}
			if kcpConn == nil {
				continue
			}
			session, ok := kcpConn.(*kcp.UDPSession)
			if !ok || session == nil {
				_ = kcpConn.Close()
				continue
			}
			session.SetNoDelay(1, 10, 2, 1)
			session.SetMtu(1400)
			session.SetWriteBuffer(4 * 1024 * 1024)
			session.SetWindowSize(256, 1024)
			dispatchRelayConnection("KCP", kcpConn, kcpHandshakeSlots, r.netGroup.ListenTCPConnection)
		}
	}()
	r.readyOnce.Do(func() { close(r.ready) })
	fmt.Println("RelayStarter Start AT " + r.addr)
	<-r.closeSignal
}

func (r *RelayStarter) Close() {
	r.closeOnce.Do(func() { close(r.closeSignal) })

	r.lifecycleMu.Lock()
	startCalled := r.startCalled
	if !startCalled && r.startErr == nil {
		r.startErr = ErrRelayStarterClosed
	}
	r.lifecycleMu.Unlock()

	if !startCalled {
		r.doneOnce.Do(func() { close(r.done) })
		return
	}
	<-r.done
}

func (r *RelayStarter) isClosing() bool {
	select {
	case <-r.closeSignal:
		return true
	default:
		return false
	}
}

func (r *RelayStarter) setStartError(err error) {
	r.lifecycleMu.Lock()
	if r.startErr == nil {
		r.startErr = err
	}
	r.lifecycleMu.Unlock()
}

// Ready closes after both TCP and KCP listeners have bound successfully.
func (r *RelayStarter) Ready() <-chan struct{} {
	return r.ready
}

// Done closes after startup fails or all listeners have been released.
func (r *RelayStarter) Done() <-chan struct{} {
	return r.done
}

// StartError reports why startup failed. It is stable after Done closes before Ready.
func (r *RelayStarter) StartError() error {
	r.lifecycleMu.RLock()
	defer r.lifecycleMu.RUnlock()
	return r.startErr
}

// Cover 返回底层 TransportCover, 供 relayNode 安装 MissingGroupHandler / RegisterHook。
func (r *RelayStarter) Cover() *TransportCover {
	return r.netGroup
}

func NewRelayStarter(listenAddr string) *RelayStarter {
	return &RelayStarter{
		addr:        listenAddr,
		netGroup:    NewTransportCover(),
		closeSignal: make(chan struct{}),
		ready:       make(chan struct{}),
		done:        make(chan struct{}),
	}
}
