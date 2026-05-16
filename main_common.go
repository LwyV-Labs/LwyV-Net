package main

import (
	"fmt"
	"log"
)

type RunMode string

const (
	RunModeClient RunMode = "client"
	RunModeServer RunMode = "server"
	RunModeGenKey RunMode = "genkey"
)

func parseRunMode(args []string) RunMode {
	if len(args) < 2 {
		return RunModeClient
	}
	switch args[1] {
	case string(RunModeGenKey):
		return RunModeGenKey
	case string(RunModeServer):
		return RunModeServer
	case string(RunModeClient):
		return RunModeClient
	default:
		log.Fatalf("%s is not a valid runType, use client/server/genkey", args[1])
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
