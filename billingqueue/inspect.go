package billingqueue

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"

	"bnfs_p2p/billingvoucher"
)

const (
	WALInspectionSchema    = "billingqueue-wal/v3"
	LegacyInspectionSchema = "billingqueue-legacy/v2"
)

// Inspection is a redacted aggregate view of a persistent waitSubmit queue.
type Inspection struct {
	Schema          string `json:"schema"`
	Depth           uint64 `json:"depth"`
	PayloadBytes    uint64 `json:"payload_bytes"`
	IncompleteTail  bool   `json:"incomplete_tail"`
	ChannelDepth    uint64 `json:"channel_depth"`
	AuthorizedBytes uint64 `json:"authorized_bytes"`
	SessionCount    uint64 `json:"session_count"`
}

// InspectionOptions selects one payer/Relay pair and supplies the public
// identities needed to verify every selected mutual voucher. RelayPublicKey is
// required for a targeted inspection. PayerPublicKey is optional when every
// selected settlement envelope contains the payer public identity.
type InspectionOptions struct {
	PayerID        billingvoucher.Identifier
	RelayID        billingvoucher.Identifier
	PayerPublicKey *ecdh.PublicKey
	RelayPublicKey *ecdh.PublicKey
}

// Inspect reads and validates an existing persistent queue without modifying it.
func Inspect(path string, limits Limits) (Inspection, error) {
	return InspectWithOptions(path, limits, InspectionOptions{})
}

// InspectWithOptions reads and validates an existing persistent queue without
// modifying it. A targeted inspection additionally verifies both signatures
// and requires each selected live channel to contain a complete sequence-1 to
// head chain. AuthorizedBytes is then the exact aggregate settlement delta
// authorized by those live chains.
func InspectWithOptions(path string, limits Limits, options InspectionOptions) (Inspection, error) {
	maximumFileSize, err := validateLimits(limits)
	if err != nil {
		return Inspection{}, err
	}
	normalizedOptions, targeted, err := normalizeInspectionOptions(options)
	if err != nil {
		return Inspection{}, err
	}
	if path == "" {
		return Inspection{}, errors.New("billingqueue: persistent queue path is required")
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return Inspection{}, fmt.Errorf("billingqueue: resolve persistent queue path: %w", err)
	}
	encoded, exists, err := readFile(absolutePath, maximumFileSize)
	if err != nil {
		return Inspection{}, err
	}
	if !exists {
		return Inspection{}, fmt.Errorf("billingqueue: inspect persistent queue: %w", os.ErrNotExist)
	}

	switch {
	case bytes.HasPrefix(encoded, []byte(fileDomain)):
		replayed, replayErr := replayWAL(encoded, limits)
		if replayErr != nil {
			return Inspection{}, replayErr
		}
		inspection := Inspection{
			Schema:         WALInspectionSchema,
			Depth:          uint64(len(replayed.items)),
			PayloadBytes:   replayed.bytes,
			IncompleteTail: replayed.validBytes != len(encoded),
		}
		if targeted {
			if err := inspectTargetChannels(&inspection, replayed.items, normalizedOptions); err != nil {
				return Inspection{}, err
			}
		}
		return inspection, nil
	case bytes.HasPrefix(encoded, []byte(legacyFileDomain)):
		items, payloadBytes, decodeErr := decodeLegacyFile(encoded, limits)
		if decodeErr != nil {
			return Inspection{}, decodeErr
		}
		liveIDs := make(map[billingvoucher.Identifier]struct{}, len(items))
		for _, item := range items {
			if _, duplicate := liveIDs[item.id]; duplicate {
				return Inspection{}, fmt.Errorf("%w: duplicate live voucher", ErrCorrupt)
			}
			liveIDs[item.id] = struct{}{}
		}
		inspection := Inspection{
			Schema:       LegacyInspectionSchema,
			Depth:        uint64(len(items)),
			PayloadBytes: payloadBytes,
		}
		if targeted {
			if err := inspectTargetChannels(&inspection, items, normalizedOptions); err != nil {
				return Inspection{}, err
			}
		}
		return inspection, nil
	default:
		return Inspection{}, fmt.Errorf("%w: invalid file domain", ErrCorrupt)
	}
}

func normalizeInspectionOptions(options InspectionOptions) (InspectionOptions, bool, error) {
	targeted := options.PayerID != (billingvoucher.Identifier{}) ||
		options.RelayID != (billingvoucher.Identifier{}) ||
		options.PayerPublicKey != nil || options.RelayPublicKey != nil
	if !targeted {
		return options, false, nil
	}
	if options.PayerPublicKey != nil {
		payerID, err := billingvoucher.NodeIDFromPublicKey(options.PayerPublicKey)
		if err != nil {
			return InspectionOptions{}, false, errors.New("billingqueue: invalid inspection payer identity")
		}
		if options.PayerID != (billingvoucher.Identifier{}) && options.PayerID != payerID {
			return InspectionOptions{}, false, errors.New("billingqueue: inspection payer identity mismatch")
		}
		options.PayerID = payerID
	}
	if options.PayerID == (billingvoucher.Identifier{}) {
		return InspectionOptions{}, false, errors.New("billingqueue: inspection payer identity is required")
	}
	if options.RelayPublicKey == nil {
		return InspectionOptions{}, false, errors.New("billingqueue: inspection Relay public identity is required")
	}
	relayID, err := billingvoucher.NodeIDFromPublicKey(options.RelayPublicKey)
	if err != nil {
		return InspectionOptions{}, false, errors.New("billingqueue: invalid inspection Relay identity")
	}
	if options.RelayID != (billingvoucher.Identifier{}) && options.RelayID != relayID {
		return InspectionOptions{}, false, errors.New("billingqueue: inspection Relay identity mismatch")
	}
	options.RelayID = relayID
	return options, true, nil
}

func inspectTargetChannels(inspection *Inspection, items []entry, options InspectionOptions) error {
	channels := make(map[channelKey][]billingvoucher.MutualVoucher)
	sessions := make(map[billingvoucher.Identifier]struct{})
	for _, item := range items {
		voucher := item.envelope.Voucher
		if voucher.Body.PayerNatID != options.PayerID || voucher.Body.PayeeRelayID != options.RelayID {
			continue
		}
		if voucher.Body.Direction != billingvoucher.DirectionPayerOutbound ||
			voucher.Body.PolicyDigest != billingvoucher.CurrentPolicyDigest() ||
			voucher.Body.AuthorizedThroughBytes != billingvoucher.MaxBillableBytes {
			return fmt.Errorf("%w: target mutual voucher uses an unsupported settlement policy", ErrCorrupt)
		}
		payerPublicKey, err := inspectionPayerPublicKey(item.envelope, options.PayerPublicKey)
		if err != nil {
			return fmt.Errorf("%w: target payer identity is unavailable", ErrCorrupt)
		}
		if err := voucher.Verify(payerPublicKey, options.RelayPublicKey); err != nil {
			return fmt.Errorf("%w: target mutual voucher signature verification failed", ErrCorrupt)
		}
		key := voucherChannel(voucher)
		channels[key] = append(channels[key], voucher)
		sessions[voucher.Body.SessionID] = struct{}{}
		inspection.ChannelDepth++
	}

	for _, chain := range channels {
		if len(chain) == 0 {
			continue
		}
		first := chain[0]
		if first.Body.Sequence != 1 || first.Body.PreviousMutualVoucherID != (billingvoucher.Identifier{}) {
			return fmt.Errorf("%w: target live channel does not contain its genesis voucher", ErrCorrupt)
		}
		for index := 1; index < len(chain); index++ {
			if err := billingvoucher.ValidateSuccessor(chain[index-1], chain[index]); err != nil {
				return fmt.Errorf("%w: target live voucher chain is invalid", ErrCorrupt)
			}
		}
		authorized := chain[len(chain)-1].Body.CumulativeUniqueBytes
		if authorized > math.MaxUint64-inspection.AuthorizedBytes {
			return fmt.Errorf("%w: target authorized byte total overflows", ErrCorrupt)
		}
		inspection.AuthorizedBytes += authorized
	}
	inspection.SessionCount = uint64(len(sessions))
	return nil
}

func inspectionPayerPublicKey(envelope Envelope, expected *ecdh.PublicKey) (*ecdh.PublicKey, error) {
	if envelope.PayerPublicKey == "" {
		if expected == nil {
			return nil, errors.New("payer public identity is missing")
		}
		return expected, nil
	}
	encoded, err := hex.DecodeString(envelope.PayerPublicKey)
	if err != nil || hex.EncodeToString(encoded) != envelope.PayerPublicKey {
		return nil, errors.New("payer public identity is not canonical")
	}
	publicKey, err := ecdh.P256().NewPublicKey(encoded)
	if err != nil {
		return nil, errors.New("payer public identity is invalid")
	}
	if expected != nil && !bytes.Equal(expected.Bytes(), publicKey.Bytes()) {
		return nil, errors.New("payer public identity does not match inspection identity")
	}
	return publicKey, nil
}
