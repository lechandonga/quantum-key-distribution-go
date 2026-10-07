package qkd

import (
	"log"
	"sync/atomic"
)

// sessionLogger emits stage-level logs containing only non-secret counters.
// It never logs raw bits, sample contents, or key material.
type sessionLogger struct {
	lg  *log.Logger
	id  string
	seq atomic.Int64
}

func (s *sessionLogger) stage(format string, args ...any) {
	if s.lg == nil {
		return
	}
	n := s.seq.Add(1)
	full := append([]any{s.id, n}, args...)
	s.lg.Printf("session=%s step=%02d "+format, full...)
}
