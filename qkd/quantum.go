package qkd

// photon 表示一个软件模拟的光子脉冲：携带经典比特及制备基矢，
// Detected=false 表示该光子在信道中丢失、探测器无响应。
type photon struct {
	bit      byte
	basis    byte // 0=Z(rectilinear) 1=X(diagonal)
	detected bool
}

// prepare 发送方制备 n 个光子：比特与基矢均来自独立确定性随机流。
func prepare(n int, rng *bitStream) []photon {
	ps := make([]photon, n)
	bits := rng.bits(n)
	bases := rng.bits(n)
	for i := range ps {
		ps[i] = photon{bit: bits[i], basis: bases[i], detected: true}
	}
	return ps
}

// transmit 模拟量子信道。
//
//   - 损耗：每个光子以 Loss 概率丢失（detected=false）；
//   - 全程窃听：窃听者对每个存活光子随机选基拦截测量，再按测量结果
//     以同一基矢重发。基矢选错（概率 1/2）时，在接收方与发送方基矢
//     一致的位置上以 1/2 概率引入翻转 => 筛后码串误码率约 25%，
//     因而抽样比例固定（默认 20%）时可被稳定检出；
//   - 噪声：存活比特以 Noise 概率翻转（独立去极化噪声）。
func transmit(ps []photon, c Config, rng *bitStream) {
	for i := range ps {
		if !ps[i].detected {
			continue
		}
		if rng.unitFloat() < c.Loss {
			ps[i].detected = false
			continue
		}
		if c.Eavesdrop {
			eb := rng.bit() // 窃听者随机选基
			m := ps[i].bit
			if eb != ps[i].basis {
				// 选错基：测量结果随机化
				m = rng.bit()
			}
			// 重发：接收方看到的光子为 (m, eb)
			ps[i].bit = m
			ps[i].basis = eb
		}
		if rng.unitFloat() < c.Noise {
			ps[i].bit ^= 1
		}
	}
}

// measure 接收方对每个存活光子随机选基测量并就地更新测量结果：
// 测量基与光子当前偏振基一致时结果确定，不一致时结果随机坍缩。
// 返回接收方选用的基矢序列（未探测位置无意义）。
func measure(ps []photon, rng *bitStream) []byte {
	bases := rng.bits(len(ps))
	for i := range ps {
		if !ps[i].detected {
			continue
		}
		if bases[i] != ps[i].basis {
			ps[i].bit = rng.bit() // 非本征态：测量结果随机
		}
		ps[i].basis = bases[i]
	}
	return bases
}

// sift 基矢筛选：双方在经过认证的经典信道上对比基矢（基矢本身可公开），
// 仅保留双方基矢一致且光子被探测到的位置。返回发送方与接收方筛后码串。
func sift(senderBits, senderBases []byte, ps []photon) (alice, bob []byte) {
	for i := range ps {
		if !ps[i].detected {
			continue
		}
		if senderBases[i] != ps[i].basis {
			continue
		}
		alice = append(alice, senderBits[i])
		bob = append(bob, ps[i].bit)
	}
	return alice, bob
}
