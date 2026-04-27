package kit

import (
	"fmt"
	"math/rand"
	"net"
	"time"
)

// RandomInterval 生成：基础时间 ± 浮动范围 的随机间隔
func RandomInterval(base, fluctuate time.Duration) time.Duration {
	// 生成 [-fluctuate, fluctuate] 之间的随机 Duration
	offset := time.Duration(rand.Int63n(2*int64(fluctuate)+1)) - fluctuate
	return base + offset
}

func MaskToPrefix(mask string) (int, error) {
	// 把点分十进制掩码（255.255.255.0）转成前缀长度（24）。
	ip := net.ParseIP(mask).To4()
	if ip == nil {
		return 0, fmt.Errorf("非法子网掩码: %s", mask)
	}
	ones, bits := net.IPMask(ip).Size()
	if bits != 32 {
		return 0, fmt.Errorf("非法子网掩码: %s", mask)
	}
	return ones, nil
}
