package qkd

import "math/rand/v2"

// bitStream 是基于 math/rand/v2 PCG 的确定性比特/随机量来源。
// 同一 Seed 下所有派生流完全可复现；不同 stream 互不相关。
type bitStream struct {
	pcg *rand.PCG
}

func newBitStream(seed uint64, stream uint64) *bitStream {
	return &bitStream{pcg: rand.NewPCG(seed, splitMix64(seed^stream^0x9E3779B97F4A7C15))}
}

func splitMix64(x uint64) uint64 {
	x += 0x9E3779B97F4A7C15
	x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9
	x = (x ^ (x >> 27)) * 0x94D049BB133111EB
	return x ^ (x >> 31)
}

func (b *bitStream) bit() byte {
	if b.pcg.Uint64()&1 == 1 {
		return 1
	}
	return 0
}

// bits 生成 n 个 0/1 字节。
func (b *bitStream) bits(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte(b.pcg.Uint64() & 1)
	}
	return out
}

func (b *bitStream) unitFloat() float64 {
	// 用高 53 位映射到 [0,1)，确定性且精度足够仿真使用。
	return float64(b.pcg.Uint64()>>11) / float64(uint64(1)<<53)
}

// permutation 返回 [0,n) 的确定性随机置换（Fisher–Yates）。
func (b *bitStream) permutation(n int) []int {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	for i := n - 1; i > 0; i-- {
		j := int(b.pcg.Uint64() % uint64(i+1))
		p[i], p[j] = p[j], p[i]
	}
	return p
}
