package relayquery

import (
	"bnfs_p2p/network"
	"testing"
)

func TestListRespRoundTrip(t *testing.T) {
	want := &ListResp{Relays: []Info{
		{NodeID: "aa11", Addr: "38.0.0.1:9000"},
		{NodeID: "bb22", Addr: "104.0.0.1:9000"},
	}}

	msg := EncodeListResp(want, "self-node-id")
	if msg.Header.RouteName != Route {
		t.Fatalf("RouteName 应为 %s, 实际 %s", Route, msg.Header.RouteName)
	}

	got, err := DecodeListResp(msg)
	if err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if len(got.Relays) != len(want.Relays) {
		t.Fatalf("relay 数不符: 期望 %d, 实际 %d", len(want.Relays), len(got.Relays))
	}
	for i := range want.Relays {
		if got.Relays[i] != want.Relays[i] {
			t.Errorf("第 %d 项不符: 期望 %+v, 实际 %+v", i, want.Relays[i], got.Relays[i])
		}
	}
}

func TestDecodeListRespBadPayload(t *testing.T) {
	bad := &network.Message{Header: &network.Header{}, Payload: []byte("not-json")}
	if _, err := DecodeListResp(bad); err == nil {
		t.Fatal("非法 payload 应返回错误")
	}
}
