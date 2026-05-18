package rardecode_test

import (
	"io"
	"testing"

	"github.com/nwaples/rardecode/v2"
)

// multiVolumeTestCase defines a test case for multi-volume archive decoding.
type multiVolumeTestCase struct {
	name      string
	archive   string
	wantFiles []struct {
		name string
		size int64
	}
	minVolumes int // minimum number of volumes expected for the largest file
}

// runMultiVolumeTest is a shared helper that opens a multi-volume archive,
// iterates all entries, reads all file data (triggering volume transitions
// and checksum verification), and validates the results.
func runMultiVolumeTest(t *testing.T, tc multiVolumeTestCase) {
	t.Helper()

	rc, err := rardecode.OpenReader(tc.archive)
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
		// Skip service headers — they appear in the Next() stream
		// but aren't regular files.
		if h.IsService {
			t.Logf("service: %q  size: %d", h.Name, h.UnPackedSize)
			continue
		}
		files = append(files, h.Name)
		t.Logf("file: %q  size: %d  packed: %d  solid: %v", h.Name, h.UnPackedSize, h.PackedSize, h.Solid)

		// Read all data — this triggers volume transitions and checksum verification
		n, err := io.Copy(io.Discard, &rc.Reader)
		if err != nil {
			t.Fatalf("Read error on %q after %d bytes: %v\n  volumes: %v",
				h.Name, n, err, rc.Volumes())
		}
		t.Logf("  read %d bytes, volumes: %v", n, rc.Volumes())
	}

	if len(files) != len(tc.wantFiles) {
		t.Fatalf("expected %d files, got %d: %v", len(tc.wantFiles), len(files), files)
	}
	for i, want := range tc.wantFiles {
		if files[i] != want.name {
			t.Errorf("file[%d] = %q, want %q", i, files[i], want.name)
		}
	}
}

// TestMultiVolumeWithQO verifies that multi-volume archives containing
// QO (Quick Open) service headers between file data blocks and
// end-of-archive markers are decoded correctly.
//
// Regression test: service headers returned by archive50.nextBlock()
// must be skipped by packedFileReader.nextBlock() when searching for
// file continuation blocks across volumes.
func TestMultiVolumeWithQO(t *testing.T) {
	runMultiVolumeTest(t, multiVolumeTestCase{
		name:    "QO service headers",
		archive: "testdata/rar5_multi_qo.part1.rar",
		wantFiles: []struct {
			name string
			size int64
		}{
			{"content.txt", 45},
			{"data.bin", 4096},
		},
		minVolumes: 3,
	})
}

// TestMultiVolumeWithCMT verifies that multi-volume archives with
// CMT (archive comment) service headers are decoded correctly.
// Comments appear in the first volume before file entries.
func TestMultiVolumeWithCMT(t *testing.T) {
	runMultiVolumeTest(t, multiVolumeTestCase{
		name:    "CMT service headers",
		archive: "testdata/rar5_multi_cmt.part1.rar",
		wantFiles: []struct {
			name string
			size int64
		}{
			{"small1.txt", 31},
			{"data.bin", 4096},
		},
		minVolumes: 3,
	})
}

// TestMultiVolumeWithRR verifies that multi-volume archives with
// RR (Recovery Record) service headers are decoded correctly.
// RR headers appear in every volume between file data and end-of-archive.
func TestMultiVolumeWithRR(t *testing.T) {
	runMultiVolumeTest(t, multiVolumeTestCase{
		name:    "RR service headers",
		archive: "testdata/rar5_multi_rr.part01.rar",
		wantFiles: []struct {
			name string
			size int64
		}{
			{"small1.txt", 31},
			{"data.bin", 4096},
		},
		minVolumes: 3,
	})
}

// TestMultiVolumeWithAllServiceHeaders verifies that multi-volume archives
// with MULTIPLE service header types (QO + RR + CMT) in the same archive
// are decoded correctly. This tests that the service-header skip loop in
// packedFileReader.nextBlock() handles N > 1 consecutive service headers.
func TestMultiVolumeWithAllServiceHeaders(t *testing.T) {
	runMultiVolumeTest(t, multiVolumeTestCase{
		name:    "QO+RR+CMT service headers",
		archive: "testdata/rar5_multi_all_svc.part01.rar",
		wantFiles: []struct {
			name string
			size int64
		}{
			{"small1.txt", 31},
			{"data.bin", 4096},
		},
		minVolumes: 3,
	})
}

// TestSolidMultiVolumeWithQO verifies that solid multi-volume archives
// with QO service headers are decoded correctly. This is the highest-risk
// scenario: solid archives share decoder state across files, and skipping
// service headers must not desynchronize the packed byte stream that feeds
// the decoder.
func TestSolidMultiVolumeWithQO(t *testing.T) {
	runMultiVolumeTest(t, multiVolumeTestCase{
		name:    "solid + QO service headers",
		archive: "testdata/rar5_solid_multi_qo.part1.rar",
		wantFiles: []struct {
			name string
			size int64
		}{
			{"small1.txt", 31},
			{"small2.txt", 19},
			{"data.bin", 4096},
			{"medium.bin", 2048},
		},
		minVolumes: 3,
	})
}
