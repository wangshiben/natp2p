package networkFrameWork

import (
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
	kcplistener, err := kcp.Listen(r.addr)
	if err != nil {
		return
	}
	go func() {
		for {
			tcpConn, err := tcpListener.Accept()
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
			err = r.netGroup.ListenTCPConnection(kcpConn)
			if err != nil {
				log.Println("ListenKCPConnection error:", err)
				continue
			}
		}
	}()
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
