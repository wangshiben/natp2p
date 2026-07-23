package billingvoucher

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const (
	currentPolicyDomain           = "BNFS/BILLING-POLICY/V1"
	currentRelayShareNumerator    = uint64(95)
	currentPolicyShareDenominator = uint64(100)
)

// CurrentPolicyDigest identifies the immutable billing policy used by the CA.
// The digest binds the unique-byte unit, the hard unsigned window and the
// cumulative 95/5 Relay/CA split including its rounding rule.
func CurrentPolicyDigest() Digest {
	artifact := make([]byte, 0, len(currentPolicyDomain)+3*8+1)
	artifact = append(artifact, currentPolicyDomain...)
	artifact = append(artifact, 0)
	var value [8]byte
	binary.BigEndian.PutUint64(value[:], CumulativeWindowBytes)
	artifact = append(artifact, value[:]...)
	binary.BigEndian.PutUint64(value[:], currentRelayShareNumerator)
	artifact = append(artifact, value[:]...)
	binary.BigEndian.PutUint64(value[:], currentPolicyShareDenominator)
	artifact = append(artifact, value[:]...)
	return sha256.Sum256(artifact)
}

// CurrentPolicyCumulativeTotals evaluates the fixed policy from the channel's
// cumulative unique-byte watermark. Taking differences between two totals
// makes settlement independent of voucher batching and retry boundaries.
func CurrentPolicyCumulativeTotals(cumulative uint64) (relay, ca uint64, err error) {
	if cumulative > MaxBillableBytes {
		return 0, 0, fmt.Errorf("billingvoucher: cumulative policy input exceeds %d", MaxBillableBytes)
	}
	quotient := cumulative / currentPolicyShareDenominator
	remainder := cumulative % currentPolicyShareDenominator
	relay = quotient*currentRelayShareNumerator + remainder*currentRelayShareNumerator/currentPolicyShareDenominator
	return relay, cumulative - relay, nil
}
