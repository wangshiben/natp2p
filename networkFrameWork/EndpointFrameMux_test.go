package networkFrameWork

import (
	"bnfs_p2p/network"
	"context"
	"net"
	"sync"
	"testing"
)

// TestMuxConnFramingRoundTrip 验证 muxConn 的读写两端：
//   - 写：把多帧拼接的字节写进去，逐帧还原经 writeFn 输出，顺序、内容、connectionId 一致；
//   - 读：把序列化帧推进 incoming，network.ReadFrame 能从 muxConn 完整读回。
func TestMuxConnFramingRoundTrip(t *testing.T) {
	var got []*network.Frame
	var mu sync.Mutex
	c := newMuxConn("conn-A", func(f *network.Frame) error {
		mu.Lock()
		got = append(got, f)
		mu.Unlock()
		return nil
	})

	frames := []*network.Frame{
		{MessageId: 1, SeqId: 0, TotalFrames: 2, FrameType: network.FrameTypeData, ConnectionId: "conn-A", Payload: []byte("hello")},
		{MessageId: 1, SeqId: 1, TotalFrames: 2, FrameType: network.FrameTypeData, ConnectionId: "conn-A", Payload: []byte("world!!")},
		{MessageId: 0, SeqId: 0, TotalFrames: 1, AckId: 864, FrameType: network.FrameTypeFrameSizeChange, ConnectionId: "conn-A"},
	}

	// 写路径：把三帧拼成一次 Write（模拟 writeFrames 批量写）。
	var blob []byte
	for _, f := range frames {
		bs, err := f.ParseToBytes()
		if err != nil {
			t.Fatalf("ParseToBytes: %v", err)
		}
		blob = append(blob, bs...)
	}
	if n, err := c.Write(blob); err != nil || n != len(blob) {
		t.Fatalf("Write: n=%d err=%v", n, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != len(frames) {
		t.Fatalf("writeFn 收到 %d 帧, 期望 %d", len(got), len(frames))
	}
	for i, f := range got {
		if f.MessageId != frames[i].MessageId || f.SeqId != frames[i].SeqId ||
			f.FrameType != frames[i].FrameType || f.ConnectionId != frames[i].ConnectionId {
			t.Errorf("帧[%d] 不匹配: got %+v want %+v", i, f, frames[i])
		}
	}

	// 读路径：把一帧序列化推入队列，ReadFrame 应完整读回。
	bs, _ := frames[0].ParseToBytes()
	c.push(bs)
	read, err := network.ReadFrame(c)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}
	if read.ConnectionId != "conn-A" || string(read.Payload) != "hello" {
		t.Errorf("读回帧不匹配: %+v", read)
	}
}

// TestEndpointMuxDispatch 验证按 connectionId demux：两个 connId 交错的帧分别落到各自 muxConn，
// 且每个新 connId 只回调 onNew 一次。
func TestEndpointMuxDispatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var newConns []string
	var mu sync.Mutex
	m := &EndpointFrameMux{
		ctx:   ctx,
		dual:  nil,
		conns: make(map[string]*muxConn),
		onNew: func(connId string, conn net.Conn) {
			mu.Lock()
			newConns = append(newConns, connId)
			mu.Unlock()
		},
	}

	mk := func(connId string, seq uint32) *network.Frame {
		return &network.Frame{MessageId: 1, SeqId: seq, TotalFrames: 3, FrameType: network.FrameTypeData, ConnectionId: connId, Payload: []byte("x")}
	}
	// 交错投递: A0, B0, A1, B1, A2, B2
	for seq := uint32(0); seq < 3; seq++ {
		m.dispatch(mk("conn-A", seq))
		m.dispatch(mk("conn-B", seq))
	}

	mu.Lock()
	if len(newConns) != 2 {
		t.Fatalf("onNew 被调 %d 次, 期望 2 (每连接一次): %v", len(newConns), newConns)
	}
	mu.Unlock()

	for _, id := range []string{"conn-A", "conn-B"} {
		c := m.conns[id]
		if c == nil {
			t.Fatalf("connId %s 没有 muxConn", id)
		}
		c.mu.Lock()
		qlen := len(c.queue)
		c.mu.Unlock()
		if qlen != 3 {
			t.Errorf("connId %s 缓冲帧数=%d, 期望 3", id, qlen)
		}
	}
}

// 编译期确保 muxConn 实现 net.Conn。
var _ net.Conn = (*muxConn)(nil)
