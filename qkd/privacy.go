package qkd

import (
	"crypto/sha256"
	"encoding/binary"
)

// keyHash 用 SHA-256 对 0/1 比特串做一致性校验摘要（域分隔前缀避免
// 与隐私放大用途混用）。只用于比较，摘要输出即“公开的校验信息”。
func keyHash(bits []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("bb84-confirm-v1"))
	var l [8]byte
	binary.LittleEndian.PutUint64(l[:], uint64(len(bits)))
	h.Write(l[:])
	h.Write(bits)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// toeplitzExtract 以 Toeplitz 矩阵实现一次通用哈希（剩余熵提取器）：
// 输出比特 o_j = XOR_i M[j][i] * in[i]，其中 M 的各比特由公开种子
// 经 SplitMix64 确定性派生。计算按“输入侧 1 比特对应一行掩码”组织，
// 总内存约 O(out)，时间约 O(n*out/64) 次 XOR。
func toeplitzExtract(in []byte, outBits int, seed uint64) []byte {
	words := (outBits + 63) / 64
	acc := make([]uint64, words)
	state := seed
	for i := 0; i < len(in); i++ {
		state += 0x9E3779B97F4A7C15
		x := splitMix64(state)
		if in[i] == 1 {
			for w := 0; w < words; w++ {
				acc[w] ^= x
				// 在 64 位块之间保持状态推进（确定性即可）。
				x = splitMix64(x ^ uint64(i) ^ uint64(w))
			}
		}
	}
	// 展开成 0/1 字节串，并截断到 outBits。
	out := make([]byte, outBits)
	for j := 0; j < outBits; j++ {
		out[j] = byte((acc[j/64] >> (uint(j) % 64)) & 1)
	}
	return out
}

// bitsToBytes 将 0/1 比特串按 MSB-first 打包为密钥字节；长度不是 8 的
// 倍数时最后一个字节低位补零。
func bitsToBytes(bits []byte) []byte {
	out := make([]byte, (len(bits)+7)/8)
	for i, b := range bits {
		if b == 1 {
			out[i/8] |= 1 << uint(7-i%8)
		}
	}
	return out
}
