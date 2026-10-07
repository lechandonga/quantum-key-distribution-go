package qkd

// errorCorrect reconciles Bob's key to Alice's with a CASCADE-style
// protocol: several passes over publicly shuffled positions with doubling
// block sizes, binary search inside odd-parity blocks, and backtracking into
// earlier passes whenever a correction flips the parity of a previous block.
// Every exchanged parity bit is public and counted in stats.LeakEC.
// The whole procedure is deterministic given the session seed.
func (s *session) errorCorrect(aKey, bKey []byte, qber float64) error {
	n := len(aKey)
	if n == 0 {
		return nil
	}
	ec := &cascade{a: aKey, b: bKey, s: s}

	k1 := 8
	if qber > 0 {
		if v := int(0.73/qber) + 1; v > k1 {
			k1 = v
		}
	}
	const maxPasses = 12
	for pass := 0; pass < maxPasses; pass++ {
		shift := pass
		if shift > 3 {
			shift = 3
		}
		size := k1 << shift
		if size > n {
			size = n
		}
		order := make([]int, n)
		for i := range order {
			order[i] = i
		}
		s.rng.Shuffle(n, func(i, j int) { order[i], order[j] = order[j], order[i] })

		var blocks [][]int
		posBlock := make([]int, n)
		for start := 0; start < n; start += size {
			end := start + size
			if end > n {
				end = n
			}
			blk := append([]int(nil), order[start:end]...)
			for _, pos := range blk {
				posBlock[pos] = len(blocks)
			}
			blocks = append(blocks, blk)
		}
		ec.blocks = append(ec.blocks, blocks)
		ec.posBlock = append(ec.posBlock, posBlock)

		corrected := 0
		for bi, blk := range blocks {
			// Re-check after each correction: a block may hide further
			// error pairs uncovered by the previous fix.
			for ec.parityOf(pass, bi, blk) {
				if pos, ok := ec.findError(blk); ok {
					ec.correctAt(pos, pass)
					corrected++
				} else {
					break
				}
			}
		}
		s.log.stage("ec pass=%d block=%d corrected=%d leak_ec=%d", pass, size, corrected, s.stats.LeakEC)
		// A zero-correction pass is not proof of convergence (an error pair
		// may share a large block), so all passes always run; the final
		// verification stage catches any residual mismatch.
	}
	return nil
}

type cascade struct {
	a, b     []byte
	s        *session
	blocks   [][][]int // blocks[pass][blockIdx] = positions
	posBlock [][]int   // posBlock[pass][pos] = blockIdx
}

func (c *cascade) parity(key []byte, idx []int) byte {
	var p byte
	for _, i := range idx {
		p ^= key[i] & 1
	}
	return p
}

// parityOf compares Alice's and Bob's block parity, disclosing one bit.
func (c *cascade) parityOf(pass, bi int, blk []int) bool {
	c.s.stats.LeakEC++
	return c.parity(c.a, blk) != c.parity(c.b, blk)
}

// findError binary-searches a single error inside blk (odd parity assumed),
// disclosing one parity bit per halving step.
func (c *cascade) findError(blk []int) (int, bool) {
	for len(blk) > 1 {
		half := blk[:len(blk)/2]
		c.s.stats.LeakEC++
		if c.parity(c.a, half) != c.parity(c.b, half) {
			blk = half
		} else {
			blk = blk[len(blk)/2:]
		}
	}
	if len(blk) == 1 && c.a[blk[0]] != c.b[blk[0]] {
		return blk[0], true
	}
	return 0, false
}

// correctAt flips Bob's bit at pos and backtracks: every block from earlier
// passes containing pos now has odd parity, so errors hidden there are
// searched and corrected recursively.
func (c *cascade) correctAt(pos, pass int) {
	c.b[pos] ^= 1
	for p := 0; p < pass; p++ {
		bi := c.posBlock[p][pos]
		blk := c.blocks[p][bi]
		if c.parityOf(p, bi, blk) {
			if next, ok := c.findError(blk); ok {
				c.correctAt(next, p)
			}
		}
	}
}
