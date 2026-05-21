//go:build ignore

package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
)

func main() {
	TEXT("filterE8ScanAVX2", NOSPLIT, "func(buf []byte, c byte) int")
	Doc("filterE8ScanAVX2 scans buf for the first occurrence of 0xe8 or c using AVX2, returning its index.")

	ConstraintExpr("amd64")

	ptr := Load(Param("buf").Base(), GP64())
	length := Load(Param("buf").Len(), GP64())
	// Define global constant for 0xe8
	e8_sym := GLOBL("filterE8Constant", RODATA)
	DATA(0, U8(0xe8))


	c_val := GP32()
	Load(Param("c"), c_val)

	// Initialize active index idx to 0
	idx := GP64()
	XORQ(idx, idx)

	// Broadcast c to YMM
	x_c := XMM()
	MOVD(c_val, x_c)
	y_c := YMM()
	VPBROADCASTB(x_c, y_c)

	// Broadcast 0xe8 to YMM
	y_e8 := YMM()
	e8_sym_mem := Mem{Base: GP64()}
	LEAQ(e8_sym, e8_sym_mem.Base)
	VPBROADCASTB(e8_sym_mem, y_e8)

	// We process 32 bytes at a time
	limit := GP64()
	MOVQ(length, limit)
	SUBQ(Imm(32), limit)

	Label("loop32")
	CMPQ(idx, limit)
	JG(LabelRef("scalar"))

	// Load 32 bytes (unaligned)
	y_src := YMM()
	VMOVDQU(Mem{Base: ptr, Index: idx, Scale: 1}, y_src)

	// Compare with y_e8 and y_c
	y_mask_e8 := YMM()
	VPCMPEQB(y_e8, y_src, y_mask_e8)

	y_mask_c := YMM()
	VPCMPEQB(y_c, y_src, y_mask_c)

	// Combine masks with OR
	y_mask := YMM()
	VPOR(y_mask_e8, y_mask_c, y_mask)

	// Extract 32-bit mask
	mask_32 := GP32()
	VPMOVMSKB(y_mask, mask_32)

	// Check if any match found
	CMPL(mask_32, Imm(0))
	JNE(LabelRef("found32"))

	// No match, advance index by 32
	ADDQ(Imm(32), idx)
	JMP(LabelRef("loop32"))

	Label("found32")
	// Find index of first matching byte
	mask_64 := GP64()
	MOVL(mask_32, mask_64.As32())
	tz_64 := GP64()
	BSFQ(mask_64, tz_64)

	// Return idx + tz_64
	ret := GP64()
	MOVQ(idx, ret)
	ADDQ(tz_64, ret)
	Store(ret, ReturnIndex(0))
	RET()

	Label("scalar")
	Store(idx, ReturnIndex(0))
	RET()

	Generate()
}
