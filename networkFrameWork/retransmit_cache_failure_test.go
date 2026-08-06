package networkFrameWork

import (
	"errors"
	"testing"

	"bnfs_p2p/network"
)

type unavailableEntropy struct{}

func (unavailableEntropy) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}

func TestRetransmitCacheEntropyFailureUsesFailClosedAccounting(t *testing.T) {
	cache := newGlobalRetransmitCacheWithEntropy(unavailableEntropy{})
	frame := &network.Frame{
		FrameType: network.FrameTypeData, ConnectionId: "connection",
		MessageId: 1, TotalFrames: 1, Payload: []byte("payload"),
	}
	if !cache.recordFrame("server", frame) || !cache.recordFrame("server", frame) {
		t.Fatal("entropy failure must account every frame instead of suppressing retransmits")
	}
	statistics := cache.snapshot()
	if statistics.FailClosed != 2 || statistics.Entries != 0 || statistics.Hits != 0 {
		t.Fatalf("unexpected fail-closed statistics: %+v", statistics)
	}
}
