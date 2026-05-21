package rardecode

import "encoding/binary"

// compress8Generic processes 8 blocks in parallel sequentially as a fallback.
func compress8Generic(ctx *avoContext) {
	for i := 0; i < 8; i++ {
		var s blake2sState
		for j := 0; j < 8; j++ {
			s.h[j] = ctx.h[j][i]
		}
		s.t[0] = ctx.t[0][i]
		s.t[1] = ctx.t[1][i]
		s.f[0] = ctx.f[0][i]
		s.f[1] = ctx.f[1][i]

		var block [64]byte
		for j := 0; j < 16; j++ {
			binary.LittleEndian.PutUint32(block[j*4:], ctx.m[j][i])
		}

		s.compress(block[:])

		for j := 0; j < 8; j++ {
			ctx.h[j][i] = s.h[j]
		}
	}
}
