//go:build ignore

package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
)

func main() {
	TEXT("filterRGBAVX2", NOSPLIT, "func(res []byte, posR int) int")
	Doc("filterRGBAVX2 processes RGB filter post-processing channel additions using AVX2/SSE, returning the next index to process.")

	ConstraintExpr("amd64")

	// Global shuffle mask for Green channel duplication:
	// R_k at 3*k, G_k at 3*k+1, B_k at 3*k+2.
	// We want to add: res[3*k] += G_k, res[3*k+2] += G_k, leaving res[3*k+1] unchanged (+0).
	// For 5 pixels in 15 bytes, the Green source indices are 1, 4, 7, 10, 13.
	mask_sym := GLOBL("filterRGBMask", RODATA)
	DATA(0, U8(1))
	DATA(1, U8(0x80))
	DATA(2, U8(1))
	DATA(3, U8(4))
	DATA(4, U8(0x80))
	DATA(5, U8(4))
	DATA(6, U8(7))
	DATA(7, U8(0x80))
	DATA(8, U8(7))
	DATA(9, U8(10))
	DATA(10, U8(0x80))
	DATA(11, U8(10))
	DATA(12, U8(13))
	DATA(13, U8(0x80))
	DATA(14, U8(13))
	DATA(15, U8(0x80))

	// Load parameters
	ptr := Load(Param("res").Base(), GP64())
	length := Load(Param("res").Len(), GP64())
	posR := Load(Param("posR"), GP64())

	// Initialize active index idx to posR
	idx := GP64()
	MOVQ(posR, idx)

	// We need at least 16 bytes to do a safe 16-byte load/store.
	// limit = length - 16
	limit := GP64()
	MOVQ(length, limit)
	SUBQ(Imm(16), limit)

	// Pre-load shuffle mask into XMM
	X_mask := XMM()
	mask_sym_mem := Mem{Base: GP64()}
	LEAQ(mask_sym, mask_sym_mem.Base)
	VMOVDQU(mask_sym_mem, X_mask)

	// Allocate temporary registers for the loop
	X_src := XMM()
	X_green := XMM()
	X_res := XMM()

	Label("loop")
	CMPQ(idx, limit)
	JG(LabelRef("done"))

	// Load 16 bytes from memory
	VMOVDQU(Mem{Base: ptr, Index: idx, Scale: 1}, X_src)

	// Shuffle to duplicate Green channel byte to Red and Blue offsets, and zero out Green offset
	VPSHUFB(X_mask, X_src, X_green)

	// Add Green channel values to Red and Blue channels
	VPADDB(X_green, X_src, X_res)

	// Store exactly 15 bytes to avoid store forwarding stalls on overlap:
	// 1. Store lower 8 bytes (bytes 0..7)
	MOVQ(X_res, Mem{Base: ptr, Index: idx, Scale: 1})

	// 2. Store next 4 bytes (bytes 8..11) using PEXTRD
	val_32 := GP32()
	PEXTRD(Imm(2), X_res, val_32)
	MOVL(val_32, Mem{Base: ptr, Index: idx, Scale: 1, Disp: 8})

	// 3. Store next 2 bytes (bytes 12..13) using PEXTRW
	val_16 := GP32()
	PEXTRW(Imm(6), X_res, val_16)
	MOVW(val_16.As16(), Mem{Base: ptr, Index: idx, Scale: 1, Disp: 12})

	// 4. Store last 1 byte (byte 14) using PEXTRB
	val_8 := GP32()
	PEXTRB(Imm(14), X_res, val_8)
	MOVB(val_8.As8(), Mem{Base: ptr, Index: idx, Scale: 1, Disp: 14})

	// Increment index by 15 (5 pixels processed)
	ADDQ(Imm(15), idx)
	JMP(LabelRef("loop"))

	Label("done")
	Store(idx, ReturnIndex(0))
	RET()

	Generate()
}
