//go:build amd64 && !purego

package rardecode

import (
	"golang.org/x/sys/cpu"
)

func init() {
	if cpu.X86.HasAVX {
		filterRGBSIMD = filterRGBAVX2
	}
}
