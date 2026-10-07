// Command qkdsim runs a local BB84 QKD simulation end to end.
package main

import (
	"context"
	"flag"
	"log"
	"os"

	"github.com/lechandonga/quantum-key-distribution-go/qkd"
)

func main() {
	var p qkd.Params
	flag.IntVar(&p.NumQubits, "qubits", 20000, "number of photons Alice prepares")
	flag.Int64Var(&p.Seed, "seed", 42, "master seed (deterministic runs)")
	flag.Float64Var(&p.ChannelLoss, "loss", 0.1, "channel photon loss probability [0,1)")
	flag.Float64Var(&p.ChannelNoise, "noise", 0.01, "channel bit-flip probability [0,0.5)")
	flag.BoolVar(&p.Eavesdrop, "eve", false, "enable intercept-resend eavesdropper")
	flag.Float64Var(&p.SampleRatio, "sample-ratio", 0.2, "fraction of sifted bits sampled for QBER")
	flag.IntVar(&p.MinSample, "min-sample", 100, "minimum effective sample size")
	flag.Float64Var(&p.QBERThreshold, "qber-threshold", 0.11, "abort threshold for estimated QBER")
	flag.IntVar(&p.SecurityParam, "security", 64, "security parameter in bits")
	flag.Parse()

	logger := log.New(os.Stderr, "qkdsim ", log.LstdFlags|log.Lmicroseconds)
	mgr := qkd.NewManager(qkd.NewKeyPool(), logger)

	res, err := mgr.RunSession(context.Background(), p)
	if err != nil {
		logger.Printf("session %s aborted: %v", res.SessionID, err)
		os.Exit(1)
	}
	logger.Printf("session %s ok: key_id=%s stats=%+v", res.SessionID, res.KeyID, res.Stats)

	key, err := mgr.Pool().Take(res.KeyID, 0)
	if err != nil {
		logger.Printf("take key: %v", err)
		os.Exit(1)
	}
	logger.Printf("key consumed: id=%s length=%d bytes (material not printed)", res.KeyID, len(key))
}
