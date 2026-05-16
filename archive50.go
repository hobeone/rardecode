package rardecode

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"hash"
	"hash/crc32"
	"io"
	"math/bits"
	"slices"
	"time"
)

const (
	// block types
	block5Arc  = 1
	block5File = 2
	block5Service = 3
	block5Encrypt = 4
	block5End     = 5

	// block flags (per spec "General archive block format", Header flags)
	block5HasExtra        = 0x0001 // extra area is present
	block5HasData         = 0x0002 // data area is present
	block5SkipIfUnknown   = 0x0004 // unknown-type blocks with this flag must be skipped when updating
	block5DataNotFirst    = 0x0008 // data area is continuing from previous volume
	block5DataNotLast     = 0x0010 // data area is continuing in next volume
	block5DependsPrecFile = 0x0020 // block depends on preceding file block
	block5PreserveChild   = 0x0040 // preserve a child block if host block is modified

	// end block flags
	endArc5NotLast = 0x0001

	// archive encryption block flags
	enc5CheckPresent = 0x0001 // password check data is present

	// main archive block flags
	arc5MultiVol = 0x0001
	arc5VolNum   = 0x0002
	arc5Solid    = 0x0004

	// file block flags
	file5IsDir          = 0x0001
	file5HasUnixMtime   = 0x0002
	file5HasCRC32       = 0x0004
	file5UnpSizeUnknown = 0x0008

	// file compression flags
	file5CompAlgorithm = 0x0000003F
	file5CompSolid     = 0x00000040
	file5CompMethod    = 0x00000380
	file5CompDictSize  = 0x00007C00
	file5CompDictFract = 0x000F8000
	file5CompV5Compat  = 0x00100000

	// file encryption record flags
	file5EncCheckPresent = 0x0001 // password check data is present
	file5EncUseMac       = 0x0002 // use MAC instead of plain checksum

	// precision time flags
	file5ExtraTimeIsUnixTime = 0x01 // is unix time_t
	file5ExtraTimeHasMTime   = 0x02 // has modification time
	file5ExtraTimeHasCTime   = 0x04 // has creation time
	file5ExtraTimeHasATime   = 0x08 // has access time
	file5ExtraTimeHasUnixNS  = 0x10 // unix nanosecond time format

	cacheSize50   = 4
	maxPbkdf2Salt = 64
	pwCheckSize   = 8
	maxKdfCount   = 24

	maxDictSize   = 0x1000000000 // maximum dictionary size 64GB
	maxHeaderSize = 0x200000     // maximum header size: https://www.rarlab.com/technote.htm
)

var (
	ErrBadPassword          = errors.New("rardecode: incorrect password")
	ErrCorruptEncryptData   = errors.New("rardecode: corrupt encryption data")
	ErrUnknownEncryptMethod = errors.New("rardecode: unknown encryption method")
	ErrPlatformIntSize      = errors.New("rardecode: platform integer size too small")
	ErrDictionaryTooLarge   = errors.New("rardecode: decode dictionary too large")
	ErrBadVolumeNumber      = errors.New("rardecode: bad volume number")
	ErrNoArchiveBlock       = errors.New("rardecode: missing archive block")
	ErrBadBlockHeader       = errors.New("rardecode: bad block header")
)

type extra struct {
	ftype uint64  // field type
	data  readBuf // field data
}

type blockHeader50 struct {
	htype    uint64 // block type
	flags    uint64
	data     readBuf // block header data
	extra    []extra // extra fields
	dataSize int64   // size of block data
}

// leHash32 wraps a hash.Hash32 to return the result of Sum in little
// endian format.
type leHash32 struct {
	hash.Hash32
}

func (h leHash32) Sum(b []byte) []byte {
	s := h.Sum32()
	return append(b, byte(s), byte(s>>8), byte(s>>16), byte(s>>24))
}

func newLittleEndianCRC32() hash.Hash {
	return leHash32{crc32.NewIEEE()}
}

// archive50 implements archiveBlockReader for RAR 5 file format archives
type archive50 struct {
	pass     []byte
	blockKey []byte                // key used to encrypt blocks
	multi    bool                  // archive is multi-volume
	solid    bool                  // is a solid archive
	keyCache [cacheSize50]struct { // encryption key cache
		kdfCount int
		salt     []byte
		keys     [][]byte
	}
}

func (a *archive50) useOldNaming() bool {
	return false
}

// calcKeys50 calculates the keys used in RAR 5 archive processing.
// The returned slice of byte slices contains 3 keys.
// Key 0 is used for block or file decryption.
// Key 1 is optionally used for file checksum calculation.
// Key 2 is optionally used for password checking.
func calcKeys50(pass, salt []byte, kdfCount int) [][]byte {
	if len(salt) > maxPbkdf2Salt {
		salt = salt[:maxPbkdf2Salt]
	}
	keys := make([][]byte, 3)
	if len(keys) == 0 {
		return keys
	}

	prf := hmac.New(sha256.New, pass)
	_, _ = prf.Write(salt)
	_, _ = prf.Write([]byte{0, 0, 0, 1})

	t := prf.Sum(nil)
	u := slices.Clone(t)

	kdfCount--

	for i, iter := range []int{kdfCount, 16, 16} {
		for iter > 0 {
			prf.Reset()
			_, _ = prf.Write(u)
			u = prf.Sum(u[:0])
			for j := range u {
				t[j] ^= u[j]
			}
			iter--
		}
		keys[i] = slices.Clone(t)
	}

	pwcheck := keys[2]
	for i, v := range pwcheck[pwCheckSize:] {
		pwcheck[i&(pwCheckSize-1)] ^= v
	}
	pwcheck = pwcheck[:pwCheckSize]
	// add checksum to end of pwcheck
	sum := sha256.Sum256(pwcheck)
	pwcheck = append(pwcheck, sum[:4]...)
	keys[2] = pwcheck

	return keys
}

// getKeys returns the the corresponding encryption keys for the given kdfcount and salt.
// It will check the password if check is provided.
func (a *archive50) getKeys(kdfCount int, salt, check []byte) ([][]byte, error) {
	var keys [][]byte

	if kdfCount > maxKdfCount {
		return nil, ErrCorruptEncryptData
	}
	kdfCount = 1 << uint(kdfCount)

	// check cache of keys for match
	for _, v := range a.keyCache {
		if kdfCount == v.kdfCount && bytes.Equal(salt, v.salt) {
			keys = v.keys
			break
		}
	}
	if keys == nil {
		// not found, calculate keys
		keys = calcKeys50(a.pass, salt, kdfCount)

		// store in cache
		copy(a.keyCache[1:], a.keyCache[:])
		a.keyCache[0].kdfCount = kdfCount
		a.keyCache[0].salt = slices.Clone(salt)
		a.keyCache[0].keys = keys
	}

	// check password
	if check != nil && !bytes.Equal(check, keys[2]) {
		return nil, ErrBadPassword
	}
	return keys, nil
}

// parseFileEncryptionRecord processes the optional file encryption record from a file header.
func (a *archive50) parseFileEncryptionRecord(b readBuf, f *fileBlockHeader) error {
	f.Encrypted = true
	ver, err := b.uvarint()
	if err != nil {
		return err
	}
	if ver != 0 {
		return ErrUnknownEncryptMethod
	}
	flags, err := b.uvarint()
	if err != nil {
		return err
	}
	if len(b) < 33 {
		return ErrCorruptEncryptData
	}
	kdfCount := int(b.byte())
	salt := slices.Clone(b.bytes(16))
	f.iv = slices.Clone(b.bytes(16))

	var check []byte
	if flags&file5EncCheckPresent > 0 {
		if len(b) < 12 {
			return ErrCorruptEncryptData
		}
		check = slices.Clone(b.bytes(12))
	}
	useMac := flags&file5EncUseMac > 0
	// only need to generate keys for first block or
	// last block if it has an optional hash key
	if a.pass == nil || !(f.first || (f.last && useMac)) {
		return nil
	}
	keys, err := a.getKeys(kdfCount, salt, check)
	if err != nil {
		return err
	}
	f.key = keys[0]
	if useMac {
		f.hashKey = keys[1]
	}
	return nil
}

func readWinFiletime(b *readBuf) (time.Time, error) {
	if len(*b) < 8 {
		return time.Time{}, ErrCorruptFileHeader
	}
	// 100-nanosecond intervals since January 1, 1601
	t := b.uint64() - 116444736000000000
	t *= 100
	sec, nsec := bits.Div64(0, t, uint64(time.Second))
	return time.Unix(int64(sec), int64(nsec)), nil
}

func readUnixTime(b *readBuf) (time.Time, error) {
	if len(*b) < 4 {
		return time.Time{}, ErrCorruptFileHeader
	}
	return time.Unix(int64(b.uint32()), 0), nil
}

func readUnixNanoseconds(b *readBuf) (time.Duration, error) {
	if len(*b) < 4 {
		return 0, ErrCorruptFileHeader
	}
	d := time.Duration(b.uint32() & 0x3fffffff)
	if d >= time.Second {
		return 0, ErrCorruptFileHeader
	}
	return d, nil
}

// parseFilePrecisionTimeRecord processes the optional high precision time record from a file header.
func (a *archive50) parseFilePrecisionTimeRecord(b *readBuf, f *fileBlockHeader) error {
	var err error
	flagsV, err := b.uvarint()
	if err != nil {
		return err
	}
	flags := flagsV
	isUnixTime := flags&file5ExtraTimeIsUnixTime > 0
	if flags&file5ExtraTimeHasMTime > 0 {
		if isUnixTime {
			f.ModificationTime, err = readUnixTime(b)
		} else {
			f.ModificationTime, err = readWinFiletime(b)
		}
		if err != nil {
			return err
		}
	}
	if flags&file5ExtraTimeHasCTime > 0 {
		if isUnixTime {
			f.CreationTime, err = readUnixTime(b)
		} else {
			f.CreationTime, err = readWinFiletime(b)
		}
		if err != nil {
			return err
		}
	}
	if flags&file5ExtraTimeHasATime > 0 {
		if isUnixTime {
			f.AccessTime, err = readUnixTime(b)
		} else {
			f.AccessTime, err = readWinFiletime(b)
		}
		if err != nil {
			return err
		}
	}
	if isUnixTime && flags&file5ExtraTimeHasUnixNS > 0 {
		if flags&file5ExtraTimeHasMTime > 0 {
			ns, err := readUnixNanoseconds(b)
			if err != nil {
				return err
			}
			f.ModificationTime = f.ModificationTime.Add(ns)
		}
		if flags&file5ExtraTimeHasCTime > 0 {
			ns, err := readUnixNanoseconds(b)
			if err != nil {
				return err
			}
			f.CreationTime = f.CreationTime.Add(ns)
		}
		if flags&file5ExtraTimeHasATime > 0 {
			ns, err := readUnixNanoseconds(b)
			if err != nil {
				return err
			}
			f.AccessTime = f.AccessTime.Add(ns)
		}
	}
	return nil
}

func (a *archive50) parseFileHeader(h *blockHeader50) (f *fileBlockHeader, err error) {
	// readBuf's fixed-size accessors (byte, uint16, uint32, uint64, bytes)
	// panic on short buffers for performance. Recover here to convert
	// index-out-of-range panics from corrupt archives into errors.
	defer func() {
		if r := recover(); r != nil {
			f = nil
			err = ErrCorruptBlockHeader
		}
	}()
	f = new(fileBlockHeader)
	f.UnixUID = -1
	f.UnixGID = -1

	f.HeaderEncrypted = a.blockKey != nil
	f.first = h.flags&block5DataNotFirst == 0
	f.last = h.flags&block5DataNotLast == 0

	flagsV, err := h.data.uvarint() // file flags
	if err != nil {
		return nil, err
	}
	flags := flagsV
	f.IsDir = flags&file5IsDir > 0
	f.UnKnownSize = flags&file5UnpSizeUnknown > 0
	unpackedSizeV, err := h.data.uvarint()
	if err != nil {
		return nil, err
	}
	f.UnPackedSize = int64(unpackedSizeV)
	f.PackedSize = h.dataSize
	attrsV, err := h.data.uvarint()
	if err != nil {
		return nil, err
	}
	f.Attributes = int64(attrsV)
	if flags&file5HasUnixMtime > 0 {
		if len(h.data) < 4 {
			return nil, ErrCorruptFileHeader
		}
		f.ModificationTime = time.Unix(int64(h.data.uint32()), 0)
	}
	if flags&file5HasCRC32 > 0 {
		if len(h.data) < 4 {
			return nil, ErrCorruptFileHeader
		}
		f.sum = slices.Clone(h.data.bytes(4))
		if f.first {
			f.hash = newLittleEndianCRC32
		}
		// Note: Same split-file limitation as BLAKE2sp hash (see case 2
		// in extra records below). For non-last parts of split files, the
		// spec says CRC32 covers packed data, not unpacked.
	}

	flagsV, err = h.data.uvarint() // compression flags
	if err != nil {
		return nil, err
	}
	flags = flagsV
	f.Solid = flags&file5CompSolid > 0
	f.arcSolid = a.solid
	method := (flags >> 7) & 7 // compression method (0 == none, 1-5 valid per spec)
	if method > 5 {
		return nil, ErrUnknownDecoder
	}
	if f.first && method != 0 {
		unpackver := flags & file5CompAlgorithm
		switch unpackver {
		case 0:
			f.decVer = decode50Ver
			f.winSize = 0x20000 << ((flags >> 10) & 0x0F)
		case 1:
			if flags&file5CompV5Compat > 0 {
				f.decVer = decode50Ver
			} else {
				f.decVer = decode70Ver
			}
			f.winSize = 0x20000 << ((flags >> 10) & 0x1F)
			f.winSize += f.winSize / 32 * int64((flags>>15)&0x1F)
		default:
			return nil, ErrUnknownDecoder
		}
	}
	hostOSV, err := h.data.uvarint()
	if err != nil {
		return nil, err
	}
	switch hostOSV {
	case 0:
		f.HostOS = HostOSWindows
	case 1:
		f.HostOS = HostOSUnix
	default:
		f.HostOS = HostOSUnknown
	}
	nlenV, err := h.data.uvarint()
	if err != nil {
		return nil, err
	}
	nlen := int(nlenV)
	if len(h.data) < nlen {
		return nil, ErrCorruptFileHeader
	}
	// Per spec "Name": Names are UTF-8 without trailing zero. Unix
	// filenames with non-UTF-8 bytes use a private-use-area encoding:
	// high ASCII chars (0x80-0xFF) are mapped to U+E080-U+E0FF and a
	// U+FFFE marker is inserted. This library stores the name as-is;
	// callers extracting on Unix should check for U+FFFE and reverse
	// the mapping to recover the original byte values.
	f.Name = string(h.data.bytes(nlen))

	// parse optional extra records
	for _, e := range h.extra {
		var err error
		switch e.ftype {
		case 1: // encryption
			if encErr := a.parseFileEncryptionRecord(e.data, f); encErr != nil {
				f.errs = append(f.errs, encErr)
			}
		case 2: // file hash
			hashType, err := e.data.uvarint()
			if err != nil {
				return nil, err
			}
			if hashType == 0 && len(e.data) >= blake2sSize256 {
				f.sum = slices.Clone(e.data.bytes(blake2sSize256))
				if f.first {
					f.hash = newBLAKE2sp
				}
				// Note: Per spec "File hash record", for files split between
				// volumes, non-last parts store a hash of the packed data in
				// the current volume, while the last part stores the unpacked
				// data hash. This library currently only verifies the hash on
				// the first (and typically only/last) block, where it hashes
				// the unpacked data. Verifying intermediate split-file parts
				// would require hashing packed data before decompression, which
				// needs architectural changes to the read pipeline.
			}
		case 3:
			err = a.parseFilePrecisionTimeRecord(&e.data, f)
		case 4: // version
			if _, err = e.data.uvarint(); err != nil { // ignore flags field
				return nil, err
			}
			versionV, err := e.data.uvarint()
			if err != nil {
				return nil, err
			}
			f.Version = int(versionV)
		case 5: // file system redirection
			redirTypeV, err := e.data.uvarint()
			if err != nil {
				return nil, err
			}
			f.RedirType = int(redirTypeV)
			redirFlagsV, err := e.data.uvarint() // redirection flags
			if err != nil {
				return nil, err
			}
			f.RedirIsDir = redirFlagsV&0x0001 != 0 // 0x0001 = link target is directory
			nlenV, err := e.data.uvarint() // name length
			if err != nil {
				return nil, err
			}
			nlen := int(nlenV)
			if len(e.data) >= nlen {
				f.RedirTarget = string(e.data.bytes(nlen))
			}
		case 6: // unix owner
			ownerFlagsV, err := e.data.uvarint()
			if err != nil {
				return nil, err
			}
			ownerFlags := ownerFlagsV
			if ownerFlags&0x01 != 0 { // user name present
				nlenV, err := e.data.uvarint()
				if err != nil {
					return nil, err
				}
				nlen := int(nlenV)
				if len(e.data) >= nlen {
					f.UnixOwner = string(e.data.bytes(nlen))
				}
			}
			if ownerFlags&0x02 != 0 { // group name present
				nlenV, err := e.data.uvarint()
				if err != nil {
					return nil, err
				}
				nlen := int(nlenV)
				if len(e.data) >= nlen {
					f.UnixGroup = string(e.data.bytes(nlen))
				}
			}
			if ownerFlags&0x04 != 0 { // numeric UID present
				uidV, err := e.data.uvarint()
				if err != nil {
					return nil, err
				}
				f.UnixUID = int(uidV)
			}
			if ownerFlags&0x08 != 0 { // numeric GID present
				gidV, err := e.data.uvarint()
				if err != nil {
					return nil, err
				}
				f.UnixGID = int(gidV)
			}
		case 7: // service data (per spec "Service data record")
			// Contents are opaque and depend on the service header type
			// (e.g., CMT for comments, QO for quick open). Store raw bytes
			// for callers to interpret.
			if len(e.data) > 0 {
				f.ServiceData = slices.Clone([]byte(e.data))
			}
		}
		if err != nil {
			return nil, err
		}
	}
	return f, nil
}

// parseEncryptionBlock calculates the key for block encryption.
func (a *archive50) parseEncryptionBlock(b readBuf) error {
	if a.pass == nil {
		return ErrArchiveEncrypted
	}
	ver, err := b.uvarint()
	if err != nil {
		return err
	}
	if ver != 0 {
		return ErrUnknownEncryptMethod
	}
	flags, err := b.uvarint()
	if err != nil {
		return err
	}
	if len(b) < 17 {
		return ErrCorruptEncryptData
	}
	kdfCount := int(b.byte())
	salt := b.bytes(16)

	var check []byte
	if flags&enc5CheckPresent > 0 {
		if len(b) < 12 {
			return ErrCorruptEncryptData
		}
		check = b.bytes(12)
	}

	keys, err := a.getKeys(kdfCount, salt, check)
	if err != nil {
		return err
	}
	a.blockKey = keys[0]
	return nil
}

func (a *archive50) parseArcBlock(h *blockHeader50) (int, error) {
	flags, err := h.data.uvarint()
	if err != nil {
		return -1, err
	}
	a.multi = flags&arc5MultiVol > 0
	a.solid = flags&arc5Solid > 0
	volnum := -1
	if flags&arc5VolNum > 0 {
		v, err := h.data.uvarint()
		if err != nil {
			return -1, err
		}
		volnum = int(v)
	}

	// Parse main archive header extra records per spec.
	// Type 0x01: Locator (quick open / recovery record offsets)
	// Type 0x02: Metadata (original archive name, creation time)
	// These are currently not exposed in the public API but are
	// parsed to validate the archive structure.
	for _, e := range h.extra {
		switch e.ftype {
		case 1: // locator record
			locFlags, err := e.data.uvarint()
			if err != nil {
				break
			}
			if locFlags&0x0001 != 0 { // quick open offset present
				if _, err = e.data.uvarint(); err != nil {
					break
				}
			}
			if locFlags&0x0002 != 0 { // recovery record offset present
				if _, err = e.data.uvarint(); err != nil {
					break
				}
			}
		case 2: // metadata record
			metaFlags, err := e.data.uvarint()
			if err != nil {
				break
			}
			if metaFlags&0x0001 != 0 { // archive name present
				nlenV, err := e.data.uvarint()
				if err != nil {
					break
				}
				nlen := int(nlenV)
				if len(e.data) >= nlen {
					_ = e.data.bytes(nlen) // consume name bytes
				}
			}
			// Note: creation time (flag 0x0002) parsing omitted for now
			// as it requires checking flags 0x0004 (unix vs FILETIME) and
			// 0x0008 (seconds vs nanoseconds) for correct size.
		}
	}
	return volnum, nil
}

func (a *archive50) readBlockHeader(r byteReader) (*blockHeader50, error) {
	if a.blockKey != nil {
		// block is encrypted
		if a.pass == nil {
			return nil, ErrArchiveEncrypted
		}
		iv := make([]byte, 16)
		_, err := io.ReadFull(r, iv)
		if err != nil {
			return nil, err
		}
		r, err = newAesDecryptReader(r, a.blockKey, iv)
		if err != nil {
			return nil, err
		}
	}
	// find the header size
	sizeBuf := make([]byte, 7)
	_, err := io.ReadFull(r, sizeBuf)
	if err != nil {
		return nil, err
	}
	b := readBuf(sizeBuf)
	crc := b.uint32()
	// Check if header size is valid
	sizeV, err := b.uvarint() // header size
	if err != nil {
		return nil, err
	}
	size := int(sizeV)
	bufSize := 3 + size - len(b)
	if bufSize < 4 || size > maxHeaderSize {
		return nil, ErrBadBlockHeader
	}

	buf := make([]byte, bufSize)
	copy(buf, sizeBuf[4:])
	_, err = io.ReadFull(r, buf[3:])
	if err != nil {
		return nil, err
	}

	// check header crc
	hash := crc32.NewIEEE()
	_, _ = hash.Write(buf)
	if crc != hash.Sum32() {
		return nil, ErrBadHeaderCRC
	}

	b = buf[3-len(b):]
	h := new(blockHeader50)
	h.htype, err = b.uvarint()
	if err != nil {
		return nil, err
	}
	h.flags, err = b.uvarint()
	if err != nil {
		return nil, err
	}

	var extraSize int
	if h.flags&block5HasExtra > 0 {
		extraSizeV, err := b.uvarint()
		if err != nil {
			return nil, err
		}
		extraSize = int(extraSizeV)
	}
	if h.flags&block5HasData > 0 {
		dataSizeV, err := b.uvarint()
		if err != nil {
			return nil, err
		}
		h.dataSize = int64(dataSizeV)
	}
	if len(b) < extraSize {
		return nil, ErrCorruptBlockHeader
	}
	h.data = b.bytes(len(b) - extraSize)

	// read header extra records
	for len(b) > 0 {
		sizeV, err := b.uvarint()
		if err != nil {
			return nil, err
		}
		size = int(sizeV)
		if len(b) < size {
			return nil, ErrCorruptBlockHeader
		}
		data := readBuf(b.bytes(size))
		ftype, err := data.uvarint()
		if err != nil {
			return nil, err
		}
		h.extra = append(h.extra, extra{ftype, data})
	}

	return h, nil
}

func (a *archive50) mustReadBlockHeader(r byteReader) (*blockHeader50, error) {
	h, err := a.readBlockHeader(r)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return h, nil
}

func (a *archive50) init(br *bufVolumeReader) (int, error) {
	a.blockKey = nil // reset encryption when opening new volume file
	volnum := -1
	h, err := a.mustReadBlockHeader(br)
	if err != nil {
		return volnum, err
	}
	if h.htype == block5Encrypt {
		err = a.parseEncryptionBlock(h.data)
		if err != nil {
			return volnum, err
		}
		h, err = a.mustReadBlockHeader(br)
		if err != nil {
			return volnum, err
		}
	}
	if h.htype != block5Arc {
		return volnum, ErrNoArchiveBlock
	}
	volnum, err = a.parseArcBlock(h)
	if err != nil {
		return volnum, err
	}
	return volnum, nil
}

// nextBlock advances to the next file block in the archive.
//
// Service headers (type 3) include archive comments (name "CMT"),
// quick open records (name "QO"), and per-file metadata (NTFS streams,
// etc.). Per spec "Quick open header", the QO record stores cached
// file headers for random-access seeking. Since this library reads
// sequentially, QO data is exposed but not specifically interpreted.
func (a *archive50) nextBlock(br *bufVolumeReader) (*fileBlockHeader, error) {
	for {
		// get next block header
		h, err := a.mustReadBlockHeader(br)
		if err != nil {
			return nil, err
		}
		switch h.htype {
		case block5File:
			return a.parseFileHeader(h)
		case block5Service:
			// Service headers (type 3) use the same structure as file headers.
			// Parse them to expose metadata (e.g., "CMT" archive comments).
			// Per spec flag 0x0020 (block5DependsPrecFile), service headers
			// typically depend on the preceding file block.
			f, err := a.parseFileHeader(h)
			if f != nil {
				f.isService = true
				f.IsService = true
			}
			return f, err
		case block5End:
			flags, err := h.data.uvarint()
			if err != nil {
				return nil, err
			}
			if flags&endArc5NotLast == 0 || !a.multi {
				return nil, io.EOF
			}
			return nil, ErrMultiVolume
		default:
			if h.dataSize > 0 {
				err = br.Discard(h.dataSize) // skip over block data
				if err != nil {
					return nil, err
				}
			}
		}
	}
}

// newArchive50 creates a new archiveBlockReader for a Version 5 archive.
func newArchive50(password *string) *archive50 {
	a := &archive50{}
	if password != nil {
		a.pass = []byte(*password)
	}
	return a
}
