package qkd

import (
	"fmt"
	"log"
	"os"
)

// Logger 是组件使用的最小日志接口。实现方必须保证不记录原始比特、
// 抽样内容或密钥材料；本包自身只输出阶段名与聚合统计量。
type Logger interface {
	Infof(session, format string, args ...any)
	Warnf(session, format string, args ...any)
}

type stdLogger struct{ l *log.Logger }

// NewStdLogger 输出到 stderr 的默认日志器，只含阶段与统计字段。
func NewStdLogger() Logger {
	return &stdLogger{l: log.New(os.Stderr, "[bb84] ", log.LstdFlags|log.Lmicroseconds)}
}

func (s *stdLogger) Infof(session, format string, args ...any) {
	s.l.Printf("INFO session=%s %s", session, fmt.Sprintf(format, args...))
}

func (s *stdLogger) Warnf(session, format string, args ...any) {
	s.l.Printf("WARN session=%s %s", session, fmt.Sprintf(format, args...))
}

type nopLogger struct{}

func (nopLogger) Infof(string, string, ...any) {}
func (nopLogger) Warnf(string, string, ...any) {}

// NopLogger 丢弃全部日志，主要用于测试。
func NopLogger() Logger { return nopLogger{} }
