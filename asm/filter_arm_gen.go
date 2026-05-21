//go:build ignore

package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
)

func main() {
	TEXT("filterArmAVX2", NOSPLIT, "func(buf []byte, offset int64) int")
	Doc("filterArmAVX2 relocates ARM branch targets using AVX2, returning the number of processed bytes.")

	ConstraintExpr("amd64")

	// Global constants
	eb_sym := GLOBL("filterArmEB", RODATA)
	DATA(0, U32(0xeb))

	mask24_sym := GLOBL("filterArmMask24", RODATA)
	DATA(0, U32(0x00ffffff))

	seq_sym := GLOBL("filterArmSeq", RODATA)
	DATA(0, U32(0))
	DATA(4, U32(1))
	DATA(8, U32(2))
	DATA(12, U32(3))
	DATA(16, U32(4))
	DATA(20, U32(5))
	DATA(24, U32(6))
	DATA(28, U32(7))

	// Load parameters
	ptr := Load(Param("buf").Base(), GP64())
	length := Load(Param("buf").Len(), GP64())
	offset := Load(Param("offset"), GP64())

	// Initialize return index idx to 0
	idx := GP64()
	XORQ(idx, idx)

	// Check if length < 32
	limit := GP64()
	MOVQ(length, limit)
	SUBQ(Imm(32), limit)
	JL(LabelRef("done"))

	// Pre-load constant registers
	Y_eb := YMM()
	eb_sym_mem := Mem{Base: GP64()}
	LEAQ(eb_sym, eb_sym_mem.Base)
	VPBROADCASTD(eb_sym_mem, Y_eb)

	Y_mask24 := YMM()
	mask24_sym_mem := Mem{Base: GP64()}
	LEAQ(mask24_sym, mask24_sym_mem.Base)
	VPBROADCASTD(mask24_sym_mem, Y_mask24)

	Y_seq := YMM()
	seq_sym_mem := Mem{Base: GP64()}
	LEAQ(seq_sym, seq_sym_mem.Base)
	VMOVDQU(seq_sym_mem, Y_seq)

	// Allocate temporary YMM registers for the loop
	Y_src := YMM()
	Y_shifted := YMM()
	Y_mask := YMM()
	Y_blend := YMM()
	Y_val := YMM()
	Y_sub := YMM()
	Y_n := YMM()
	Y_temp1 := YMM()
	Y_temp2 := YMM()
	Y_res := YMM()

	X_temp := XMM()
	Y_base := YMM()

	Label("loop")
	CMPQ(idx, limit)
	JG(LabelRef("done"))

	// Load 32 bytes from memory
	VMOVDQU(Mem{Base: ptr, Index: idx, Scale: 1}, Y_src)

	// Shift each dword right by 24 to align the 4th byte
	VPSRLD(Imm(24), Y_src, Y_shifted)

	// Compare with broadcasted 0xeb
	VPCMPEQD(Y_eb, Y_shifted, Y_mask)

	// Y_blend = Y_mask & 0x00ffffff
	VPAND(Y_mask24, Y_mask, Y_blend)

	// Compute base = (offset + idx) / 4
	base_val := GP64()
	MOVQ(offset, base_val)
	ADDQ(idx, base_val)
	SHRQ(Imm(2), base_val)

	// Broadcast base to YMM
	base_val_32 := GP32()
	MOVL(base_val.As32(), base_val_32)
	MOVD(base_val_32, X_temp)
	VPBROADCASTD(X_temp, Y_base)

	// Y_sub = Y_base + Y_seq
	VPADDD(Y_seq, Y_base, Y_sub)

	// Y_val = Y_src & 0x00ffffff
	VPAND(Y_mask24, Y_src, Y_val)

	// Y_n = Y_val - Y_sub
	VPSUBD(Y_sub, Y_val, Y_n)

	// result = (Y_n & Y_blend) | (Y_src & ~Y_blend)
	VPAND(Y_blend, Y_n, Y_temp1)
	VPANDN(Y_src, Y_blend, Y_temp2)
	VPOR(Y_temp1, Y_temp2, Y_res)

	// Store result back to memory
	VMOVDQU(Y_res, Mem{Base: ptr, Index: idx, Scale: 1})

	// Increment idx by 32
	ADDQ(Imm(32), idx)
	JMP(LabelRef("loop"))

	Label("done")
	Store(idx, ReturnIndex(0))
	RET()

	Generate()
}
