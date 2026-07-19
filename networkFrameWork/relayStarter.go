package networkFrameWork

import (
	"bnfs_p2p/logx"
	"fmt"
	"github.com/xtaci/kcp-go/v5"
	"net"
)

const relayHandshakeConcurrency = 128

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
	addr     string // 监听地址
	netGroup *TransportCover
	close    chan interface{}
}

func (r *RelayStarter) StartListen() {
	tcpListener, err := net.Listen("tcp", r.addr)
	if err != nil {
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
		_ = tcpListener.Close()
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
	fmt.Println("RelayStarter Start AT " + r.addr)
	select {
	case <-r.close:
		tcpListener.Close()
		kcplistener.Close()
	}
	defer func() {
		recover()
	}()
}

func (r *RelayStarter) Close() {
	r.close <- struct{}{}
}

// Cover 返回底层 TransportCover, 供 relayNode 安装 MissingGroupHandler / RegisterHook。
func (r *RelayStarter) Cover() *TransportCover {
	return r.netGroup
}

func NewRelayStarter(listenAddr string) *RelayStarter {
	return &RelayStarter{
		addr:     listenAddr,
		netGroup: NewTransportCover(),
		close:    make(chan interface{}),
	}
}
