//go:build amd64 && !purego

package rardecode

import (
	"golang.org/x/sys/cpu"
)

func init() {
	if cpu.X86.HasAVX2 {
		filterE8ScanSIMD = filterE8ScanAVX2
	}
}
