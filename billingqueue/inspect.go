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

// Inspection 是持久化 waitSubmit 队列脱敏后的聚合视图。
type Inspection struct {
	Schema          string `json:"schema"`
	Depth           uint64 `json:"depth"`
	PayloadBytes    uint64 `json:"payload_bytes"`
	IncompleteTail  bool   `json:"incomplete_tail"`
	ChannelDepth    uint64 `json:"channel_depth"`
	AuthorizedBytes uint64 `json:"authorized_bytes"`
	SessionCount    uint64 `json:"session_count"`
}

// InspectionOptions 选择一组付款方与 Relay，并提供验证所选双签凭证需要的公开身份。
// 定向检查必须提供 RelayPublicKey；如果每个结算信封都包含付款方公开身份，
// 则 PayerPublicKey 可以省略。
type InspectionOptions struct {
	PayerID               billingvoucher.Identifier
	RelayID               billingvoucher.Identifier
	PayerPublicKey        *ecdh.PublicKey
	PayerBillingPublicKey *ecdh.PublicKey
	RelayPublicKey        *ecdh.PublicKey
	RelayBillingPublicKey *ecdh.PublicKey
}

// Inspect 只读检查并验证现有持久化队列，不修改其中内容。
func Inspect(path string, limits Limits) (Inspection, error) {
	return InspectWithOptions(path, limits, InspectionOptions{})
}

// InspectWithOptions 只读检查并验证现有持久化队列。
// 定向检查还会验证双方签名，并要求每个选中活动通道都具备从序号 1 到当前队首的完整链。
// AuthorizedBytes 是这些活动链授权的精确结算增量总和。
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
		options.PayerPublicKey != nil || options.PayerBillingPublicKey != nil ||
		options.RelayPublicKey != nil || options.RelayBillingPublicKey != nil
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
	if options.RelayBillingPublicKey == nil {
		options.RelayBillingPublicKey = options.RelayPublicKey
	}
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
		payerPublicKey, err := inspectionPayerPublicKey(
			item.envelope, options.PayerPublicKey, options.PayerBillingPublicKey,
		)
		if err != nil {
			return fmt.Errorf("%w: target payer identity is unavailable", ErrCorrupt)
		}
		if err := voucher.VerifyBillingSignatures(payerPublicKey, options.RelayBillingPublicKey); err != nil {
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

func inspectionPayerPublicKey(
	envelope Envelope,
	expectedIdentity *ecdh.PublicKey,
	expectedBilling *ecdh.PublicKey,
) (*ecdh.PublicKey, error) {
	if envelope.PayerPublicKey == "" {
		if expectedIdentity == nil {
			return nil, errors.New("payer public identity is missing")
		}
		if expectedBilling != nil {
			return expectedBilling, nil
		}
		return expectedIdentity, nil
	}
	encoded, err := hex.DecodeString(envelope.PayerPublicKey)
	if err != nil || hex.EncodeToString(encoded) != envelope.PayerPublicKey {
		return nil, errors.New("payer public identity is not canonical")
	}
	publicKey, err := ecdh.P256().NewPublicKey(encoded)
	if err != nil {
		return nil, errors.New("payer public identity is invalid")
	}
	if expectedIdentity != nil && !bytes.Equal(expectedIdentity.Bytes(), publicKey.Bytes()) {
		return nil, errors.New("payer public identity does not match inspection identity")
	}
	signingPublicKey := publicKey
	if envelope.PayerBillingPublicKey != "" {
		encodedBilling, err := hex.DecodeString(envelope.PayerBillingPublicKey)
		if err != nil || hex.EncodeToString(encodedBilling) != envelope.PayerBillingPublicKey {
			return nil, errors.New("payer billing identity is not canonical")
		}
		signingPublicKey, err = ecdh.P256().NewPublicKey(encodedBilling)
		if err != nil {
			return nil, errors.New("payer billing identity is invalid")
		}
	}
	if expectedBilling != nil && !bytes.Equal(expectedBilling.Bytes(), signingPublicKey.Bytes()) {
		return nil, errors.New("payer billing identity does not match inspection identity")
	}
	return signingPublicKey, nil
}
