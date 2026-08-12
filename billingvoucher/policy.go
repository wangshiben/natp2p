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

// CurrentPolicyDigest 标识 CA 使用的不可变计费策略。
// 摘要绑定唯一字节计量单位、硬性未签名窗口以及包含舍入规则的 Relay/CA 累计 95/5 分成。
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

// CurrentPolicyCumulativeTotals 根据通道累计唯一字节水位计算固定策略总额。
// 通过两个累计值求差，使结算结果不受凭证批次和重试边界影响。
func CurrentPolicyCumulativeTotals(cumulative uint64) (relay, ca uint64, err error) {
	if cumulative > MaxBillableBytes {
		return 0, 0, fmt.Errorf("billingvoucher: cumulative policy input exceeds %d", MaxBillableBytes)
	}
	quotient := cumulative / currentPolicyShareDenominator
	remainder := cumulative % currentPolicyShareDenominator
	relay = quotient*currentRelayShareNumerator + remainder*currentRelayShareNumerator/currentPolicyShareDenominator
	return relay, cumulative - relay, nil
}
