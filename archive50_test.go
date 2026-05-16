package rardecode

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"testing"
)

func TestReadBlockHeaderZeroSize(t *testing.T) {
	// Header size of 0 should be rejected as corrupt.
	// Build: [CRC32 (4 bytes)] [size vint = 0] [padding to 7 bytes]
	sizeVint := encodeVint(0)
	data := append(sizeVint, 0x01) // dummy header type
	hash := crc32.NewIEEE()
	hash.Write(data)
	crcVal := hash.Sum32()

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, crcVal)
	buf.Write(data)
	for buf.Len() < 7 {
		buf.WriteByte(0)
	}

	a := &archive50{}
	_, err := a.readBlockHeader(&buf)
	if err != ErrCorruptBlockHeader {
		t.Errorf("expected ErrCorruptBlockHeader for zero-size header, got: %v", err)
	}
}

func TestReadBlockHeaderOversizedVint(t *testing.T) {
	// A 4+ byte vint exceeds the 3-byte limit for header size in the 7-byte
	// initial read buffer, so it hits ErrTruncatedVint before our size check.
	// This tests that corrupt large headers are still rejected.
	//
	// Build a vint that needs 4 bytes: value = 2097152 (2MB + 1 byte in 7-bit groups)
	// This exceeds the 3 remaining bytes in sizeBuf after CRC32.
	sizeVint := encodeVint(2097152)
	if len(sizeVint) <= 3 {
		t.Fatalf("expected 4+ byte vint, got %d bytes", len(sizeVint))
	}

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint32(0)) // dummy CRC
	buf.Write(sizeVint)
	for buf.Len() < 7 {
		buf.WriteByte(0)
	}

	a := &archive50{}
	_, err := a.readBlockHeader(&buf)
	if err == nil {
		t.Error("expected error for oversized header, got nil")
	}
	// Should get ErrTruncatedVint since the vint exceeds the 3-byte read buffer
	if err != ErrTruncatedVint {
		t.Logf("got error (acceptable): %v", err)
	}
}

func TestReadBlockHeaderMaxValid(t *testing.T) {
	// Max valid 3-byte vint = 2097151 (2MB - 1), which is within the 2MB limit.
	// This should NOT be rejected by the size check (though it will fail later
	// when trying to read that much data from the empty buffer).
	sizeVint := encodeVint(2097151)
	if len(sizeVint) != 3 {
		t.Fatalf("expected 3-byte vint, got %d bytes", len(sizeVint))
	}

	// CRC covers everything after CRC field
	data := make([]byte, 0, 3)
	data = append(data, sizeVint...)
	hash := crc32.NewIEEE()
	hash.Write(data)
	crcVal := hash.Sum32()

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, crcVal)
	buf.Write(data)

	a := &archive50{}
	_, err := a.readBlockHeader(&buf)
	// Should NOT get ErrCorruptBlockHeader — it should get past size validation
	// and fail later (likely on io.ReadFull for the header body)
	if err == ErrCorruptBlockHeader {
		t.Error("2MB-1 header should pass size validation")
	}
}

// encodeVint encodes a uint64 as a RAR5 vint (variable-length integer).
func encodeVint(v uint64) []byte {
	var buf []byte
	for v >= 0x80 {
		buf = append(buf, byte(v&0x7F)|0x80)
		v >>= 7
	}
	buf = append(buf, byte(v))
	return buf
}
