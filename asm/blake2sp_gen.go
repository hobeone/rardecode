//go:build ignore

package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

// Dummy definition to satisfy the avo stub parser
type avoContext struct {
	h [8][8]uint32
	t [2][8]uint32
	f [2][8]uint32
	m [16][8]uint32
}

// BLAKE2s sigma table (message permutation schedule)
var blake2sSigma = [10][16]byte{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
}

func Ymm(i int) Register {
	switch i {
	case 0: return Y0
	case 1: return Y1
	case 2: return Y2
	case 3: return Y3
	case 4: return Y4
	case 5: return Y5
	case 6: return Y6
	case 7: return Y7
	case 8: return Y8
	case 9: return Y9
	case 10: return Y10
	case 11: return Y11
	case 12: return Y12
	case 13: return Y13
	}
	panic("invalid register index")
}

func main() {
	TEXT("compress8AVX2", NOSPLIT, "func(ctx *byte)")
	Doc("compress8AVX2 runs BLAKE2s compression on 8 blocks in parallel using AVX2.")

	ConstraintExpr("amd64")

	// Define the static BLAKE2s IV
	blake2sIV_sym := GLOBL("blake2spIV", RODATA)
	DATA(0, U32(0x6a09e667))
	DATA(4, U32(0xbb67ae85))
	DATA(8, U32(0x3c6ef372))
	DATA(12, U32(0xa54ff53a))
	DATA(16, U32(0x510e527f))
	DATA(20, U32(0x9b05688c))
	DATA(24, U32(0x1f83d9ab))
	DATA(28, U32(0x5be0cd19))

	// Load ptr to avoContext
	ctxPtr := Load(Param("ctx"), GP64())
	ctx := Mem{Base: ctxPtr}

	// 1. Load h[0] to h[7] into Y0 to Y7
	for i := 0; i < 8; i++ {
		VMOVDQU(ctx.Offset(i*32), Ymm(i))
	}

	// 2. Initialize v8 to v11 to IV[0] to IV[3]
	ivPtr := GP64()
	LEAQ(blake2sIV_sym, ivPtr)
	
	VPBROADCASTD(Mem{Base: ivPtr, Disp: 0}, Y8)
	VPBROADCASTD(Mem{Base: ivPtr, Disp: 4}, Y9)
	VPBROADCASTD(Mem{Base: ivPtr, Disp: 8}, Y10)
	VPBROADCASTD(Mem{Base: ivPtr, Disp: 12}, Y11)

	// Allocate stack memory for spilled v[14] and v[15]
	v14_stack := AllocLocal(32)
	v15_stack := AllocLocal(32)

	// v12 = IV[4] ^ t[0]
	VPBROADCASTD(Mem{Base: ivPtr, Disp: 16}, Y15)
	VMOVDQU(ctx.Offset(256), Y12) // ctx.t[0]
	VPXOR(Y15, Y12, Y12)

	// v13 = IV[5] ^ t[1]
	VPBROADCASTD(Mem{Base: ivPtr, Disp: 20}, Y15)
	VMOVDQU(ctx.Offset(288), Y13) // ctx.t[1]
	VPXOR(Y15, Y13, Y13)

	// v14 = IV[6] ^ f[0]
	VPBROADCASTD(Mem{Base: ivPtr, Disp: 24}, Y15)
	VMOVDQU(ctx.Offset(320), Y14) // ctx.f[0] using Y14 as temp
	VPXOR(Y15, Y14, Y14)
	VMOVDQU(Y14, v14_stack)

	// v15 = IV[7] ^ f[1]
	VPBROADCASTD(Mem{Base: ivPtr, Disp: 28}, Y15)
	VMOVDQU(ctx.Offset(352), Y14) // ctx.f[1] using Y14 as temp
	VPXOR(Y15, Y14, Y14)
	VMOVDQU(Y14, v15_stack)

	// Run the 10 rounds of mixing
	for round := 0; round < 10; round++ {
		sig := blake2sSigma[round]
		// Column steps
		generateG(0, 4, 8, 12, sig[0], sig[1], ctx, v14_stack, v15_stack)
		generateG(1, 5, 9, 13, sig[2], sig[3], ctx, v14_stack, v15_stack)
		generateG(2, 6, 10, 14, sig[4], sig[5], ctx, v14_stack, v15_stack)
		generateG(3, 7, 11, 15, sig[6], sig[7], ctx, v14_stack, v15_stack)
		// Diagonal steps
		generateG(0, 5, 10, 15, sig[8], sig[9], ctx, v14_stack, v15_stack)
		generateG(1, 6, 11, 12, sig[10], sig[11], ctx, v14_stack, v15_stack)
		generateG(2, 7, 8, 13, sig[12], sig[13], ctx, v14_stack, v15_stack)
		generateG(3, 4, 9, 14, sig[14], sig[15], ctx, v14_stack, v15_stack)
	}

	// 4. Finalization: ctx.h[i] ^= v[i] ^ v[i+8]
	for i := 0; i < 6; i++ {
		VPXOR(Ymm(i), Ymm(i+8), Y15)
		VMOVDQU(ctx.Offset(i*32), Y14) // reuse Y14 as temp load
		VPXOR(Y14, Y15, Y15)
		VMOVDQU(Y15, ctx.Offset(i*32))
	}

	// For i == 6: v14 is in v14_stack
	VMOVDQU(v14_stack, Y15)
	VPXOR(Y6, Y15, Y15)
	VMOVDQU(ctx.Offset(6*32), Y14)
	VPXOR(Y14, Y15, Y15)
	VMOVDQU(Y15, ctx.Offset(6*32))

	// For i == 7: v15 is in v15_stack
	VMOVDQU(v15_stack, Y15)
	VPXOR(Y7, Y15, Y15)
	VMOVDQU(ctx.Offset(7*32), Y14)
	VPXOR(Y14, Y15, Y15)
	VMOVDQU(Y15, ctx.Offset(7*32))

	RET()
	Generate()
}

func generateG(a, b, c, d int, x_idx, y_idx byte, ctx Mem, v14_stack, v15_stack Mem) {
	regA := Ymm(a)
	regB := Ymm(b)
	regC := Ymm(c)
	
	var regD Register
	if d == 14 {
		regD = Y14
		VMOVDQU(v14_stack, regD)
	} else if d == 15 {
		regD = Y14
		VMOVDQU(v15_stack, regD)
	} else {
		regD = Ymm(d)
	}

	x := ctx.Offset(384 + int(x_idx)*32)
	y := ctx.Offset(384 + int(y_idx)*32)

	// v[a] = v[a] + v[b] + x
	VPADDD(regB, regA, regA)
	VPADDD(x, regA, regA)

	// v[d] = bits.RotateLeft32(v[d]^v[a], -16)
	VPXOR(regA, regD, regD)
	rotateRight(regD, 16, Y15)

	// v[c] = v[c] + v[d]
	VPADDD(regD, regC, regC)

	// v[b] = bits.RotateLeft32(v[b]^v[c], -12)
	VPXOR(regC, regB, regB)
	rotateRight(regB, 12, Y15)

	// v[a] = v[a] + v[b] + y
	VPADDD(regB, regA, regA)
	VPADDD(y, regA, regA)

	// v[d] = bits.RotateLeft32(v[d]^v[a], -8)
	VPXOR(regA, regD, regD)
	rotateRight(regD, 8, Y15)

	// v[c] = v[c] + v[d]
	VPADDD(regD, regC, regC)

	// v[b] = bits.RotateLeft32(v[b]^v[c], -7)
	VPXOR(regC, regB, regB)
	rotateRight(regB, 7, Y15)

	if d == 14 {
		VMOVDQU(regD, v14_stack)
	} else if d == 15 {
		VMOVDQU(regD, v15_stack)
	}
}

func rotateRight(reg Register, n uint8, tmp Register) {
	VPSRLD(Imm(uint64(n)), reg, tmp)
	VPSLLD(Imm(uint64(32-n)), reg, reg)
	VPOR(tmp, reg, reg)
}
