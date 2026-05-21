package rardecode

import (
	"bytes"
	"fmt"
	"testing"
)

func TestFilterDelta_ZeroChannels(t *testing.T) {
	buf := []byte{1, 2, 3, 4}
	got, err := filterDelta(0, buf)
	if err != nil {
		t.Fatal(err)
	}
	if &got[0] != &buf[0] {
		t.Error("expected original buf returned for n=0")
	}
}

func TestFilterDelta_ExcessiveChannels(t *testing.T) {
	buf := []byte{1, 2, 3}
	got, err := filterDelta(10, buf)
	if err != nil {
		t.Fatal(err)
	}
	if &got[0] != &buf[0] {
		t.Error("expected original buf returned for n > len(buf)")
	}
}

func TestFilterDelta_ValidInput(t *testing.T) {
	buf := []byte{1, 2, 3, 4}
	got, err := filterDelta(2, buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("expected 4 bytes, got %d", len(got))
	}
	expected := []byte{255, 253, 253, 249}
	for i, v := range expected {
		if got[i] != v {
			t.Errorf("got[%d] = %d, want %d", i, got[i], v)
		}
	}
}

func TestFilterRGBV3_SmallR0(t *testing.T) {
	r := map[int]uint32{0: 0, 1: 0}
	buf := []byte{1, 2, 3, 4, 5, 6}
	got, err := filterRGBV3(r, nil, buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if &got[0] != &buf[0] {
		t.Error("expected original buf returned for r[0]=0")
	}
}

func filterArmGeneric(buf []byte, offset int64) []byte {
	for i := 0; len(buf)-i > 3; i += 4 {
		if buf[i+3] == 0xeb {
			n := uint(buf[i])
			n += uint(buf[i+1]) * 0x100
			n += uint(buf[i+2]) * 0x10000
			n -= (uint(offset) + uint(i)) / 4
			buf[i] = byte(n)
			buf[i+1] = byte(n >> 8)
			buf[i+2] = byte(n >> 16)
		}
	}
	return buf
}

func TestFilterArm(t *testing.T) {
	sizes := []int{0, 3, 4, 15, 32, 35, 64, 100, 1024, 1024 + 13}
	for _, size := range sizes {
		buf1 := make([]byte, size)
		buf2 := make([]byte, size)
		for i := 0; i < size; i++ {
			if i%4 == 3 && i%8 == 3 {
				buf1[i] = 0xeb
			} else {
				buf1[i] = byte(i * 17)
			}
		}
		copy(buf2, buf1)

		offset := int64(12345)
		got, err := filterArm(buf1, offset)
		if err != nil {
			t.Fatal(err)
		}
		expected := filterArmGeneric(buf2, offset)
		if !bytes.Equal(got, expected) {
			t.Fatalf("size %d: got %x, want %x", size, got, expected)
		}
	}
}

func BenchmarkFilterArm_Comparison(b *testing.B) {
	for _, size := range []int{32, 1024, 65536} {
		buf1 := make([]byte, size)
		for i := 0; i < size; i++ {
			if i%4 == 3 {
				buf1[i] = 0xeb
			}
		}
		buf2 := make([]byte, size)
		copy(buf2, buf1)

		b.Run(fmt.Sprintf("Generic/%d", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = filterArmGeneric(buf1, 100)
			}
		})

		b.Run(fmt.Sprintf("AVX2/%d", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = filterArm(buf2, 100)
			}
		})
	}
}

func filterRGBGeneric(res []byte, posR int) []byte {
	for i := posR; i < len(res)-2; i += 3 {
		c := res[i+1]
		res[i] += c
		res[i+2] += c
	}
	return res
}

func TestFilterRGB(t *testing.T) {
	sizes := []int{0, 2, 3, 5, 14, 15, 17, 30, 45, 100, 1000}
	for _, size := range sizes {
		buf1 := make([]byte, size)
		buf2 := make([]byte, size)
		for i := 0; i < size; i++ {
			buf1[i] = byte(i*3 + 7)
		}
		copy(buf2, buf1)

		posR := 0
		if size > 5 {
			posR = 3
		}

		var start int = posR
		if filterRGBSIMD != nil {
			start = filterRGBSIMD(buf1, posR)
		}
		for i := start; i < len(buf1)-2; i += 3 {
			c := buf1[i+1]
			buf1[i] += c
			buf1[i+2] += c
		}

		expected := filterRGBGeneric(buf2, posR)
		if !bytes.Equal(buf1, expected) {
			t.Fatalf("size %d: got %x, want %x", size, buf1, expected)
		}
	}
}

func BenchmarkFilterRGB_Comparison(b *testing.B) {
	for _, size := range []int{15, 1020, 65535} {
		buf1 := make([]byte, size)
		for i := 0; i < size; i++ {
			buf1[i] = byte(i)
		}
		buf2 := make([]byte, size)
		copy(buf2, buf1)

		b.Run(fmt.Sprintf("Generic/%d", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = filterRGBGeneric(buf1, 0)
			}
		})

		b.Run(fmt.Sprintf("AVX/%d", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				var start int
				if filterRGBSIMD != nil {
					start = filterRGBSIMD(buf2, 0)
				}
				for i := start; i < len(buf2)-2; i += 3 {
					c := buf2[i+1]
					buf2[i] += c
					buf2[i+2] += c
				}
			}
		})
	}
}

func TestFilterE8(t *testing.T) {
	sizes := []int{0, 4, 5, 10, 31, 32, 33, 64, 100, 1024, 1024 + 17}
	for _, size := range sizes {
		for _, c := range []byte{0xe8, 0xe9} {
			for _, v5 := range []bool{false, true} {
				buf1 := make([]byte, size)
				for i := 0; i < size; i++ {
					if i%17 == 3 {
						buf1[i] = 0xe8
					} else if i%17 == 7 {
						buf1[i] = 0xe9
					} else {
						buf1[i] = byte(i * 13)
					}
				}
				buf2 := make([]byte, size)
				copy(buf2, buf1)

				savedSIMD := filterE8ScanSIMD
				filterE8ScanSIMD = nil
				gotGeneric, err := filterE8(c, v5, buf1, 1000)
				if err != nil {
					t.Fatal(err)
				}

				filterE8ScanSIMD = savedSIMD
				gotSIMD, err := filterE8(c, v5, buf2, 1000)
				if err != nil {
					t.Fatal(err)
				}

				if !bytes.Equal(gotGeneric, gotSIMD) {
					t.Fatalf("size=%d, c=%x, v5=%v: SIMD result does not match Generic.\nGeneric: %x\nSIMD:    %x", size, c, v5, gotGeneric, gotSIMD)
				}
			}
		}
	}
}

func BenchmarkFilterE8_Comparison(b *testing.B) {
	for _, size := range []int{32, 1024, 65536} {
		buf1 := make([]byte, size)
		for i := 0; i < size; i++ {
			if i%128 == 0 {
				buf1[i] = 0xe8
			} else {
				buf1[i] = byte(i)
			}
		}
		buf2 := make([]byte, size)
		copy(buf2, buf1)

		b.Run(fmt.Sprintf("Generic/%d", size), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				savedSIMD := filterE8ScanSIMD
				filterE8ScanSIMD = nil
				_, _ = filterE8(0xe9, false, buf1, 100)
				filterE8ScanSIMD = savedSIMD
			}
		})

		b.Run(fmt.Sprintf("AVX2/%d", size), func(b *testing.B) {
			if filterE8ScanSIMD == nil {
				b.Skip("AVX2 scanning is not available")
			}
			for i := 0; i < b.N; i++ {
				_, _ = filterE8(0xe9, false, buf2, 100)
			}
		})
	}
}


