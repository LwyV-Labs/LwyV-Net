package kit

import (
	"math/rand"
	"time"
)

// RandomInterval 生成：基础时间 ± 浮动范围 的随机间隔
func RandomInterval(base, fluctuate time.Duration) time.Duration {
	// 生成 [-fluctuate, fluctuate] 之间的随机 Duration
	offset := time.Duration(rand.Int63n(2*int64(fluctuate)+1)) - fluctuate
	return base + offset
}
