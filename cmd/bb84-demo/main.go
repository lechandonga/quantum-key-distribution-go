// bb84-demo 在本地演示一次正常会话、一次全程窃听会话与一次样本不足会话。
package main

import (
	"fmt"

	"github.com/lechandonga/quantum-key-distribution-go/qkd"
)

func main() {
	mgr := qkd.NewManager(qkd.NewStdLogger())

	cases := []struct {
		name string
		cfg  qkd.Config
	}{
		{"normal", qkd.Config{Seed: 42, Photons: 20000, Loss: 0.1, Noise: 0.01}},
		{"eavesdropped", qkd.Config{Seed: 42, Photons: 20000, Loss: 0.1, Noise: 0.01, Eavesdrop: true}},
		{"high_loss", qkd.Config{Seed: 7, Photons: 2000, Loss: 0.95, Noise: 0.01, MinSifted: 64}},
	}
	for _, tc := range cases {
		s, err := mgr.Run(tc.cfg, qkd.SecurityStandard)
		if err != nil {
			fmt.Printf("[%s] aborted: reason=%s qber=%.4f\n", tc.name, qkd.ReasonOf(err), s.Stats.QBER)
			continue
		}
		k, err := mgr.Acquire(s.KeyID, qkd.SecurityStandard)
		fmt.Printf("[%s] ok key_bits=%d key_bytes=%d qber=%.4f acquire_err=%v\n",
			tc.name, s.Stats.FinalKeyBits, len(k.Material), s.Stats.QBER, err)
	}
}
