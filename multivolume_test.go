package rardecode_test

import (
	"io"
	"testing"

	"github.com/nwaples/rardecode/v2"
)

// TestMultiVolumeWithServiceHeaders verifies that multi-volume archives
// containing service headers (e.g., QO quick open records) between file
// data blocks and end-of-archive markers are decoded correctly.
//
// This is a regression test: service headers returned by archive50.nextBlock()
// must be skipped by packedFileReader.nextBlock() when searching for file
// continuation blocks across volumes.
func TestMultiVolumeWithServiceHeaders(t *testing.T) {
	rc, err := rardecode.OpenReader("testdata/rar5_multi_qo.part1.rar")
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()

	var files []string
	for {
		h, err := rc.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Next() error: %v (files so far: %v)", err, files)
		}
		// Skip service headers (QO, CMT, etc.) — they appear in the
		// Next() stream but aren't regular files.
		if h.Name == "QO" || h.Name == "CMT" || h.Name == "RR" {
			continue
		}
		files = append(files, h.Name)
		t.Logf("file: %q  size: %d  packed: %d", h.Name, h.UnPackedSize, h.PackedSize)

		// Read all data — this triggers volume transitions and checksum verification
		n, err := io.Copy(io.Discard, &rc.Reader)
		if err != nil {
			t.Fatalf("Read error on %q after %d bytes: %v\n  volumes: %v",
				h.Name, n, err, rc.Volumes())
		}
		t.Logf("  read %d bytes, volumes: %v", n, rc.Volumes())
	}

	if len(files) != 2 {
		t.Fatalf("expected 2 files, got %d: %v", len(files), files)
	}
	if files[0] != "content.txt" {
		t.Errorf("first file = %q, want %q", files[0], "content.txt")
	}
	if files[1] != "data.bin" {
		t.Errorf("second file = %q, want %q", files[1], "data.bin")
	}
}
