package qkd

// sampleResult 是抽样误码率估计阶段的输出（只含统计量，不含抽样内容）。
type sampleResult struct {
	sampleSize int
	errors     int
	qber       float64
}

// estimateQBER 双方从筛后码串的相同位置（由确定性置换决定）抽出
// sampleCount 个比特并公开比对。抽样比特必须从后续密钥材料中永久剔除。
// 返回剔除抽样后的双方码串、统计结果。
func estimateQBER(alice, bob []byte, sampleCount int, rng *bitStream) (ra, rb []byte, res sampleResult) {
	perm := rng.permutation(len(alice))
	sampled := perm[:sampleCount]
	keep := perm[sampleCount:]

	errs := 0
	for _, idx := range sampled {
		if alice[idx] != bob[idx] {
			errs++
		}
	}

	ra = make([]byte, len(keep))
	rb = make([]byte, len(keep))
	for j, idx := range keep {
		ra[j] = alice[idx]
		rb[j] = bob[idx]
	}
	return ra, rb, sampleResult{sampleSize: sampleCount, errors: errs, qber: float64(errs) / float64(sampleCount)}
}

// reconcile 实现确定性的 Cascade 风格信息协调：
//
//  1. 每轮用独立确定性流派生随机置换，并按块长切分；
//  2. 双方公开每个块的奇偶校验（1 比特泄露）；奇偶不同的块用
//     二分法定位 1 个错误并翻转，二分中公开的每个子段奇偶
//     （1 比特）同样计入泄露；
//  3. 块长按 8→16→… 倍增，覆盖“小块内偶数个错误”的残留；
//  4. 整块长序列跑完后重新置换再扫，直到 SHA-256 一致性哈希
//     通过为止；为避免异常噪声导致死循环，设扫描轮数上限，
//     超限且哈希仍不一致即中止会话（绝不放行可能不一致的密钥）。
func reconcile(alice, bob []byte, seed uint64, faults Faults, log Logger, sid string) (rbOut []byte, blockLeak int, err error) {
	rb := make([]byte, len(bob))
	copy(rb, bob)

	const maxPasses = 8
	pass := 0
	for keyHash(alice) != keyHash(rb) {
		if pass >= maxPasses {
			return nil, blockLeak, fail(ReasonReconcileHash,
				"residual errors remain after %d reconciliation passes; confirmation failed", maxPasses)
		}
		for _, block := range []int{8, 64, 512} {
			rr := newBitStream(seed, uint64(1000+pass*32+block))
			perm := rr.permutation(len(rb))
			for start := 0; start < len(perm); start += block {
				end := start + block
				if end > len(perm) {
					end = len(perm)
				}
				fixBlock(alice, rb, perm[start:end], &blockLeak)
			}
			log.Infof(sid, "reconcile pass=%d block_size=%d leak=%d", pass+1, block, blockLeak)
		}
		pass++
	}

	if faults.FlipAfterReconcile {
		rb[0] ^= 1
	}
	if keyHash(alice) != keyHash(rb) {
		return nil, blockLeak, fail(ReasonReconcileHash,
			"post-reconcile confirmation hash mismatch; keys are not consistent")
	}
	log.Infof(sid, "reconcile confirmation=passed passes=%d leak=%d", pass, blockLeak)
	return rb, blockLeak, nil
}

// fixBlock 比较整块奇偶；不一致时二分定位并翻转一个错误比特。
// 每公开一个奇偶值（整块或二分左段）记 1 比特泄露。
func fixBlock(alice, rb []byte, idx []int, leak *int) {
	*leak = *leak + 1
	if parityAt(alice, idx) == parityAt(rb, idx) {
		return
	}
	lo, hi := 0, len(idx)
	for hi-lo > 1 {
		mid := lo + (hi-lo)/2
		*leak = *leak + 1
		if parityAt(alice, idx[lo:mid]) != parityAt(rb, idx[lo:mid]) {
			hi = mid
		} else {
			lo = mid
		}
	}
	rb[idx[lo]] ^= 1
}

func parityAt(bits []byte, idx []int) byte {
	var p byte
	for _, i := range idx {
		p ^= bits[i]
	}
	return p
}
