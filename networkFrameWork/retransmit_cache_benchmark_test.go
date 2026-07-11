package networkFrameWork

import (
	"bnfs_p2p/network"
	"testing"
)

func BenchmarkGlobalRetransmitCacheRecordAndBatchAck(b *testing.B) {
	cache := newGlobalRetransmitCache()
	payload := make([]byte, network.DefaultMaxFramePayload)
	frame := &network.Frame{
		FrameType:    network.FrameTypeData,
		ConnectionId: "benchmark-connection",
		TotalFrames:  100,
		Payload:      payload,
	}
	ackRanges := network.FullAckRange(frame.TotalFrames)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for frameIndex := 0; frameIndex < b.N; frameIndex++ {
		frame.MessageId = uint64(frameIndex / int(frame.TotalFrames))
		frame.SeqId = uint32(frameIndex % int(frame.TotalFrames))
		cache.recordFrame("benchmark-server", frame)
		if frame.SeqId == frame.TotalFrames-1 {
			cache.acknowledge(
				"benchmark-server", frame.ConnectionId, frame.MessageId, frame.TotalFrames, ackRanges,
			)
		}
	}
}

func BenchmarkGlobalRetransmitCacheExactHit(b *testing.B) {
	cache := newGlobalRetransmitCache()
	payload := make([]byte, network.DefaultMaxFramePayload)
	frame := &network.Frame{
		FrameType:    network.FrameTypeData,
		ConnectionId: "benchmark-hit-connection",
		MessageId:    1,
		TotalFrames:  1,
		Payload:      payload,
	}
	cache.recordFrame("benchmark-server", frame)
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		if iteration%retransmitCacheMaxFreeRepeats == 0 {
			frame.MessageId++
			cache.recordFrame("benchmark-server", frame)
		}
		cache.recordFrame("benchmark-server", frame)
	}
}
