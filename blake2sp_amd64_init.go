//go:build amd64 && !purego

package rardecode

import (
	"golang.org/x/sys/cpu"
	"unsafe"
)

func init() {
	if cpu.X86.HasAVX2 {
		compress8 = func(ctx *avoContext) {
			compress8AVX2((*byte)(unsafe.Pointer(ctx)))
		}
	}
}
