package main

import (
	"fmt"
	"log"
)

type RunMode string

const (
	RunModeClient RunMode = "client"
	RunModeServer RunMode = "server"
)

func parseRunMode(args []string) string {
	if len(args) < 2 {
		return string(RunModeClient)
	}
	switch args[1] {
	case "genkey", string(RunModeServer), string(RunModeClient):
		return args[1]
	default:
		log.Fatalf("%s is not a valid runType", args[1])
		return ""
	}
}

func formatBytes(b uint64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	v := float64(b)
	i := 0
	for v >= 1024 && i < len(units)-1 {
		v /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d%s", b, units[i])
	}
	return fmt.Sprintf("%.2f%s", v, units[i])
}

func formatSpeed(bps float64) string {
	if bps < 0 {
		bps = 0
	}
	return formatBytes(uint64(bps))
}
