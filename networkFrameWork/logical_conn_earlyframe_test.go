package networkFrameWork

import (
	"testing"
)

// TestMuxStream_EarlyFrameBeforeHook reproduces the cross-relay striped assembly race:
// a striped leg (legCount>1) receives DATA frames BEFORE the LogicalConn attaches its
// reassembler hook (which only happens once all M legs are collected).  Those early
// frames must be buffered and replayed on hook attach — not dropped — otherwise the
// reassembler stalls on the seq gap and the handshake hangs (observed as the real-link
// "max retransmits / TLS EOF" width>1 failure).
func TestMuxStream_EarlyFrameBeforeHook(t *testing.T) {
	st := &MuxStream{
		id:       "earlyframe",
		dataCh:   make(chan struct{}, 1),
		closedCh: make(chan struct{}),
	}
	// Mark as a striped leg (legCount>1) so deliverSeq buffers instead of using raw buf.
	st.openInfo = muxOpenInfo{legCount: 4}

	// Frames arrive BEFORE the hook is set (the race window).
	st.deliverSeq(0, []byte("AAAA"))
	st.deliverSeq(1, []byte("BBBB"))
	st.deliverSeq(2, []byte("CCCC"))

	// Now attach the reassembler hook (simulating NewStripedConn after all legs collected).
	got := make([]pendingSeqChunk, 0, 3)
	st.setDeliverHook(func(seq uint64, data []byte) {
		cp := make([]byte, len(data))
		copy(cp, data)
		got = append(got, pendingSeqChunk{seq: seq, data: cp})
	})

	// All three early frames must be replayed in order.
	if len(got) != 3 {
		t.Fatalf("expected 3 replayed early frames, got %d", len(got))
	}
	for i, want := range []string{"AAAA", "BBBB", "CCCC"} {
		if got[i].seq != uint64(i) || string(got[i].data) != want {
			t.Fatalf("frame %d: got seq=%d data=%q, want seq=%d data=%q",
				i, got[i].seq, got[i].data, i, want)
		}
	}

	// Frames after the hook is set go straight through.
	var late []byte
	st.setDeliverHook(func(seq uint64, data []byte) { late = append(late, data...) })
	st.deliverSeq(3, []byte("DDDD"))
	if string(late) != "DDDD" {
		t.Fatalf("post-hook frame: got %q want DDDD", late)
	}
	t.Logf("✔ early striped frames buffered before hook + replayed in order (seq 0,1,2), no loss")
}
