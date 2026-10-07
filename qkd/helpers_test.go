package qkd

import (
	"fmt"
	"time"
)

func sprintf(format string, args ...any) string { return fmt.Sprintf(format, args...) }

// statsCore 去除耗时字段后比较，耗时不参与“可复现性”定义。
func statsCore(s Stats) Stats {
	s.Duration = time.Duration(0)
	return s
}
