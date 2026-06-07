package networkFrameWork

import (
	"fmt"
	"github.com/xtaci/kcp-go/v5"
	"log"
	"net"
)

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
		return
	}
	go func() {
		for {
			tcpConn, err := tcpListener.Accept()
			if err != nil {
				return
			}
			if tcpConn == nil {
				continue
			}
			err = r.netGroup.ListenTCPConnection(tcpConn)
			if err != nil {
				log.Println("ListenTCPConnection error:", err)
				continue
			}
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
				continue
			}
			session.SetNoDelay(1, 50, 2, 1)
			session.SetMtu(1000)
			session.SetWriteBuffer(4 * 1024 * 1024)
			session.SetWindowSize(128, 512)
			err = r.netGroup.ListenTCPConnection(kcpConn)
			if err != nil {
				log.Println("ListenKCPConnection error:", err)
				continue
			}
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

func NewRelayStarter(listenAddr string) *RelayStarter {
	return &RelayStarter{
		addr:     listenAddr,
		netGroup: NewTransportCover(),
		close:    make(chan interface{}),
	}
}
