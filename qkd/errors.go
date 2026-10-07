package qkd

import "fmt"

// FailReason 以可程序化判断的方式区分会话中止/取用失败的原因。
type FailReason string

const (
	// ReasonInvalidConfig 参数组合非法（抽样比例、阈值、噪声等越界）。
	ReasonInvalidConfig FailReason = "invalid_config"
	// ReasonTooFewSamples 存活光子或有效样本数低于最低要求，无法安全估计误码率。
	ReasonTooFewSamples FailReason = "too_few_samples"
	// ReasonQBERExceeded 抽样误码率超过安全阈值。
	ReasonQBERExceeded FailReason = "qber_exceeded"
	// ReasonReconcileParity 纠错过程中双方对同一块的奇偶校验不一致（信道/模拟故障）。
	ReasonReconcileParity FailReason = "reconcile_parity_mismatch"
	// ReasonReconcileHash 纠错后一致性校验（哈希）不通过。
	ReasonReconcileHash FailReason = "reconcile_hash_mismatch"
	// ReasonKeyTooShort 扣除全部公开信息量与安全参数后剩余密钥长度不足。
	ReasonKeyTooShort FailReason = "key_too_short"
	// ReasonKeyUnknown 取用了未知的密钥标识。
	ReasonKeyUnknown FailReason = "key_unknown"
	// ReasonKeyConsumed 密钥已被取用，不能重复领取。
	ReasonKeyConsumed FailReason = "key_consumed"
	// ReasonSecurityLevel 取用方要求的安全等级高于密钥登记等级。
	ReasonSecurityLevel FailReason = "security_level_too_high"
	// ReasonPoolExhausted 密钥池没有满足条件的可用密钥。
	ReasonPoolExhausted FailReason = "pool_exhausted"
	// ReasonSessionAborted 会话已中止，不存在可领取的成果。
	ReasonSessionAborted FailReason = "session_aborted"
)

// SessionError 携带可区分失败原因的错误。
type SessionError struct {
	Reason  FailReason
	Message string
}

func (e *SessionError) Error() string {
	return fmt.Sprintf("bb84: %s: %s", e.Reason, e.Message)
}

func fail(reason FailReason, format string, args ...any) *SessionError {
	return &SessionError{Reason: reason, Message: fmt.Sprintf(format, args...)}
}

// ReasonOf 返回错误对应的 FailReason；非本包错误返回空串。
func ReasonOf(err error) FailReason {
	if err == nil {
		return ""
	}
	if se, ok := err.(*SessionError); ok {
		return se.Reason
	}
	return ""
}
