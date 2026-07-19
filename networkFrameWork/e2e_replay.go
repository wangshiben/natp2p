package networkFrameWork

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const (
	e2eMessageIDSize    = 44
	e2eSessionIDSize    = 32
	e2eReplayWindowSize = 65536
)

var errInvalidE2EMessageID = errors.New("invalid E2E message ID")

type e2eReplayWindow struct {
	initialized bool
	sessionID   [e2eSessionIDSize]byte
	highest     uint64
	seen        [e2eReplayWindowSize / 64]uint64
}

func (window *e2eReplayWindow) observe(messageID []byte) (bool, error) {
	if len(messageID) != e2eMessageIDSize {
		return false, errInvalidE2EMessageID
	}
	epoch := binary.BigEndian.Uint32(messageID[32:36])
	sequence := binary.BigEndian.Uint64(messageID[36:44])
	if epoch == 0 || sequence == 0 {
		return false, errInvalidE2EMessageID
	}
	if !window.initialized {
		copy(window.sessionID[:], messageID[:e2eSessionIDSize])
		window.initialized = true
	} else if !bytes.Equal(window.sessionID[:], messageID[:e2eSessionIDSize]) {
		return false, errors.New("E2E message ID belongs to another session")
	}

	if sequence > window.highest {
		window.advance(sequence)
	} else if window.highest-sequence >= e2eReplayWindowSize {
		return true, nil
	}

	word, mask := replayWindowSlot(sequence)
	if window.seen[word]&mask != 0 {
		return true, nil
	}
	window.seen[word] |= mask
	return false, nil
}

func (window *e2eReplayWindow) advance(sequence uint64) {
	advance := sequence - window.highest
	if advance >= e2eReplayWindowSize {
		clear(window.seen[:])
	} else {
		for offset := uint64(1); offset <= advance; offset++ {
			word, mask := replayWindowSlot(window.highest + offset)
			window.seen[word] &^= mask
		}
	}
	window.highest = sequence
}

func replayWindowSlot(sequence uint64) (uint64, uint64) {
	slot := sequence % e2eReplayWindowSize
	return slot / 64, uint64(1) << (slot % 64)
}
