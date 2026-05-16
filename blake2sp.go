package rardecode

// blake2sp implements BLAKE2sp, the 8-way parallel tree hashing variant of
// BLAKE2s, as used by RAR5 archives for file integrity verification.
//
// BLAKE2sp uses a two-level tree:
//   - 8 leaf BLAKE2s instances (fanout=8, depth=2, node_depth=0, node_offset=0..7)
//   - 1 root BLAKE2s instance (fanout=8, depth=2, node_depth=1)
//
// Input bytes are interleaved across the 8 leaves in round-robin order with
// a block size of 64 bytes (BLAKE2s block size). The root hashes the
// concatenation of the 8 leaf digests.
//
// Reference: https://blake2.net/blake2.pdf, Section 2.2 and Appendix A.
// Reference C implementation: https://github.com/BLAKE2/BLAKE2/blob/master/ref/blake2sp-ref.c

import (
	"encoding/binary"
	"hash"
	"math/bits"
)

// BLAKE2s constants
const (
	blake2sBlockSize = 64
	blake2sSize256   = 32
	blake2spFanout   = 8
)

// BLAKE2s IV
var blake2sIV = [8]uint32{
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
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

// blake2sState represents the internal state of a BLAKE2s hash.
type blake2sState struct {
	h        [8]uint32              // hash state
	t        [2]uint32              // counter
	f        [2]uint32              // finalization flags
	buf      [blake2sBlockSize]byte // block buffer
	bufLen   int                    // number of bytes in buf
	outLen   int                    // output size in bytes
	lastNode bool                   // set for the last node at each tree level
}

// blake2sParam is the 32-byte parameter block for BLAKE2s.
type blake2sParam struct {
	digestLength byte
	keyLength    byte
	fanout       byte
	depth        byte
	leafLength   uint32
	nodeOffset   uint32
	xofLength    uint16
	nodeDepth    byte
	innerLength  byte
	salt         [8]byte
	personal     [8]byte
}

// bytes returns the parameter block as a 32-byte slice.
func (p *blake2sParam) bytes() [32]byte {
	var b [32]byte
	b[0] = p.digestLength
	b[1] = p.keyLength
	b[2] = p.fanout
	b[3] = p.depth
	binary.LittleEndian.PutUint32(b[4:], p.leafLength)
	binary.LittleEndian.PutUint32(b[8:], p.nodeOffset)
	binary.LittleEndian.PutUint16(b[12:], p.xofLength)
	b[14] = p.nodeDepth
	b[15] = p.innerLength
	copy(b[16:], p.salt[:])
	copy(b[24:], p.personal[:])
	return b
}

// initBlake2s initializes a BLAKE2s state with the given parameter block.
func initBlake2s(s *blake2sState, p *blake2sParam) {
	pb := p.bytes()
	s.outLen = int(p.digestLength)
	s.h = blake2sIV
	// XOR IV with parameter block (interpreted as 8 little-endian uint32s)
	for i := range s.h {
		s.h[i] ^= binary.LittleEndian.Uint32(pb[i*4:])
	}
	s.t = [2]uint32{0, 0}
	s.f = [2]uint32{0, 0}
	s.bufLen = 0
	s.lastNode = false
}

// g is the BLAKE2s mixing function.
func g(v *[16]uint32, a, b, c, d int, x, y uint32) {
	v[a] = v[a] + v[b] + x
	v[d] = bits.RotateLeft32(v[d]^v[a], -16)
	v[c] = v[c] + v[d]
	v[b] = bits.RotateLeft32(v[b]^v[c], -12)
	v[a] = v[a] + v[b] + y
	v[d] = bits.RotateLeft32(v[d]^v[a], -8)
	v[c] = v[c] + v[d]
	v[b] = bits.RotateLeft32(v[b]^v[c], -7)
}

// compress performs the BLAKE2s compression on a single block.
func (s *blake2sState) compress(block []byte) {
	var m [16]uint32
	for i := range m {
		m[i] = binary.LittleEndian.Uint32(block[i*4:])
	}

	v := [16]uint32{
		s.h[0], s.h[1], s.h[2], s.h[3],
		s.h[4], s.h[5], s.h[6], s.h[7],
		blake2sIV[0], blake2sIV[1], blake2sIV[2], blake2sIV[3],
		blake2sIV[4] ^ s.t[0], blake2sIV[5] ^ s.t[1],
		blake2sIV[6] ^ s.f[0], blake2sIV[7] ^ s.f[1],
	}

	for i := 0; i < 10; i++ {
		sig := &blake2sSigma[i]
		g(&v, 0, 4, 8, 12, m[sig[0]], m[sig[1]])
		g(&v, 1, 5, 9, 13, m[sig[2]], m[sig[3]])
		g(&v, 2, 6, 10, 14, m[sig[4]], m[sig[5]])
		g(&v, 3, 7, 11, 15, m[sig[6]], m[sig[7]])
		g(&v, 0, 5, 10, 15, m[sig[8]], m[sig[9]])
		g(&v, 1, 6, 11, 12, m[sig[10]], m[sig[11]])
		g(&v, 2, 7, 8, 13, m[sig[12]], m[sig[13]])
		g(&v, 3, 4, 9, 14, m[sig[14]], m[sig[15]])
	}

	for i := range s.h {
		s.h[i] ^= v[i] ^ v[i+8]
	}
}

// update adds data to the BLAKE2s state.
func (s *blake2sState) update(data []byte) {
	if len(data) == 0 {
		return
	}

	// fill buffer
	if s.bufLen > 0 {
		n := copy(s.buf[s.bufLen:], data)
		s.bufLen += n
		data = data[n:]
		if s.bufLen == blake2sBlockSize && len(data) > 0 {
			s.t[0] += uint32(blake2sBlockSize)
			if s.t[0] < uint32(blake2sBlockSize) {
				s.t[1]++
			}
			s.compress(s.buf[:])
			s.bufLen = 0
		}
	}

	// process full blocks (keep at least 1 byte for final block)
	for len(data) > blake2sBlockSize {
		s.t[0] += uint32(blake2sBlockSize)
		if s.t[0] < uint32(blake2sBlockSize) {
			s.t[1]++
		}
		s.compress(data[:blake2sBlockSize])
		data = data[blake2sBlockSize:]
	}

	// buffer remaining
	if len(data) > 0 {
		copy(s.buf[:], data)
		s.bufLen = len(data)
	}
}

// finalize computes the final hash, writing the digest.
func (s *blake2sState) finalize() []byte {
	// pad remaining buffer with zeros
	for i := s.bufLen; i < blake2sBlockSize; i++ {
		s.buf[i] = 0
	}
	s.t[0] += uint32(s.bufLen)
	if s.t[0] < uint32(s.bufLen) {
		s.t[1]++
	}
	s.f[0] = 0xFFFFFFFF // set finalization flag
	if s.lastNode {
		s.f[1] = 0xFFFFFFFF // set last node flag
	}
	s.compress(s.buf[:])

	out := make([]byte, s.outLen)
	for i := 0; i < s.outLen; i++ {
		out[i] = byte(s.h[i/4] >> (8 * (i % 4)))
	}
	return out
}

// blake2sp implements hash.Hash for the BLAKE2sp parallel hash.
type blake2sp struct {
	leaves [blake2spFanout]blake2sState
	root   blake2sState
	buf    [blake2spFanout * blake2sBlockSize]byte // interleave buffer
	bufLen int
}

// newBLAKE2sp creates a new BLAKE2sp hash.Hash.
func newBLAKE2sp() hash.Hash {
	h := new(blake2sp)
	h.Reset()
	return h
}

// Reset resets the hash to its initial state.
func (h *blake2sp) Reset() {
	// Initialize 8 leaf instances
	for i := 0; i < blake2spFanout; i++ {
		p := &blake2sParam{
			digestLength: blake2sSize256,
			fanout:       blake2spFanout,
			depth:        2,
			nodeOffset:   uint32(i),
			nodeDepth:    0,
			innerLength:  blake2sSize256,
		}
		initBlake2s(&h.leaves[i], p)
		// Override outLen for leaves: they produce innerLength bytes
		h.leaves[i].outLen = blake2sSize256
	}
	// Mark last leaf
	h.leaves[blake2spFanout-1].lastNode = true

	// Initialize root instance
	p := &blake2sParam{
		digestLength: blake2sSize256,
		fanout:       blake2spFanout,
		depth:        2,
		nodeOffset:   0,
		nodeDepth:    1,
		innerLength:  blake2sSize256,
	}
	initBlake2s(&h.root, p)
	h.root.lastNode = true

	h.bufLen = 0
}

// BlockSize returns the BLAKE2sp block size (8 * 64 = 512 bytes).
func (h *blake2sp) BlockSize() int {
	return blake2spFanout * blake2sBlockSize
}

// Size returns the digest size in bytes (32).
func (h *blake2sp) Size() int {
	return blake2sSize256
}

// Write adds data to the hash.
func (h *blake2sp) Write(p []byte) (int, error) {
	nn := len(p)

	// Fill interleave buffer
	if h.bufLen > 0 {
		n := copy(h.buf[h.bufLen:], p)
		h.bufLen += n
		p = p[n:]
		if h.bufLen == len(h.buf) {
			h.distributeBlock(h.buf[:])
			h.bufLen = 0
		}
	}

	// Process full interleave blocks
	stride := blake2spFanout * blake2sBlockSize
	for len(p) > stride {
		h.distributeBlock(p[:stride])
		p = p[stride:]
	}

	// Buffer remaining
	if len(p) > 0 {
		copy(h.buf[:], p)
		h.bufLen = len(p)
	}

	return nn, nil
}

// distributeBlock distributes a full interleave block across the 8 leaves.
// Each leaf gets one blake2sBlockSize chunk.
func (h *blake2sp) distributeBlock(data []byte) {
	for i := 0; i < blake2spFanout; i++ {
		off := i * blake2sBlockSize
		h.leaves[i].update(data[off : off+blake2sBlockSize])
	}
}

// Sum appends the current hash to b and returns the resulting slice.
func (h *blake2sp) Sum(b []byte) []byte {
	// Clone state so Sum doesn't modify the original
	var leaves [blake2spFanout]blake2sState
	for i := range leaves {
		leaves[i] = h.leaves[i]
	}

	// Distribute remaining buffered data across leaves
	remaining := h.bufLen
	for i := 0; i < blake2spFanout && remaining > 0; i++ {
		off := i * blake2sBlockSize
		n := remaining
		if n > blake2sBlockSize {
			n = blake2sBlockSize
		}
		leaves[i].update(h.buf[off : off+n])
		remaining -= n
	}

	// Finalize each leaf and feed into root
	root := h.root // clone root
	for i := 0; i < blake2spFanout; i++ {
		leafDigest := leaves[i].finalize()
		root.update(leafDigest)
	}

	// Finalize root
	digest := root.finalize()
	return append(b, digest...)
}
