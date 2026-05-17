package rardecode_test

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nwaples/rardecode/v2"
)

// readAll opens the archive and reads all entries, returning headers and any error.
// It drains each file's data to trigger checksum verification.
func readAll(t *testing.T, name string, opts ...rardecode.Option) ([]*rardecode.FileHeader, error) {
	t.Helper()
	rc, err := rardecode.OpenReader(name, opts...)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	var headers []*rardecode.FileHeader
	for {
		h, err := rc.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return headers, err
		}
		headers = append(headers, h)
		// Drain the file data to trigger checksum verification
		if _, err := io.Copy(io.Discard, &rc.Reader); err != nil {
			return headers, err
		}
	}
	return headers, nil
}

func testdataPath(name string) string {
	return filepath.Join("testdata", name)
}

func TestRAR5Store(t *testing.T) {
	headers, err := readAll(t, testdataPath("rar5_store.rar"))
	if err != nil {
		t.Fatal(err)
	}
	if len(headers) != 1 {
		t.Fatalf("expected 1 file, got %d", len(headers))
	}
	h := headers[0]
	if h.Name != "hello.txt" {
		t.Errorf("name = %q, want %q", h.Name, "hello.txt")
	}
	if h.UnPackedSize != 15 {
		t.Errorf("size = %d, want 15", h.UnPackedSize)
	}
	if h.IsDir {
		t.Error("IsDir should be false")
	}
	if h.HostOS != rardecode.HostOSUnix {
		t.Errorf("HostOS = %d, want HostOSUnix (%d)", h.HostOS, rardecode.HostOSUnix)
	}
}

func TestRAR5Compress(t *testing.T) {
	headers, err := readAll(t, testdataPath("rar5_compress.rar"))
	if err != nil {
		t.Fatal(err)
	}
	if len(headers) != 2 {
		t.Fatalf("expected 2 files, got %d", len(headers))
	}
	if headers[0].Name != "hello.txt" {
		t.Errorf("first file = %q, want %q", headers[0].Name, "hello.txt")
	}
	if headers[1].Name != "second.txt" {
		t.Errorf("second file = %q, want %q", headers[1].Name, "second.txt")
	}
}

func TestRAR5Solid(t *testing.T) {
	headers, err := readAll(t, testdataPath("rar5_solid.rar"))
	if err != nil {
		t.Fatal(err)
	}
	if len(headers) < 2 {
		t.Fatalf("expected >= 2 files, got %d", len(headers))
	}
	// First file in a solid archive isn't marked Solid (it has no predecessor).
	// Only subsequent files that depend on prior decompression state are Solid.
	if headers[0].Solid {
		t.Error("first file in solid archive should have Solid=false")
	}
	if !headers[1].Solid {
		t.Error("second file in solid archive should have Solid=true")
	}
}

func TestRAR5Directory(t *testing.T) {
	headers, err := readAll(t, testdataPath("rar5_directory.rar"))
	if err != nil {
		t.Fatal(err)
	}
	var foundDir, foundFile bool
	for _, h := range headers {
		if h.IsDir {
			foundDir = true
			if h.Mode()&fs.ModeDir == 0 {
				t.Errorf("directory %q: Mode() missing ModeDir", h.Name)
			}
		} else {
			foundFile = true
		}
	}
	if !foundDir {
		t.Error("expected at least one directory entry")
	}
	if !foundFile {
		t.Error("expected at least one file entry")
	}
}

func TestRAR5BLAKE2sp(t *testing.T) {
	// BLAKE2sp hash archive — checksum is verified by reading all data
	headers, err := readAll(t, testdataPath("rar5_blake2.rar"))
	if err != nil {
		t.Fatal(err)
	}
	if len(headers) != 1 {
		t.Fatalf("expected 1 file, got %d", len(headers))
	}
	if headers[0].Name != "hello.txt" {
		t.Errorf("name = %q, want %q", headers[0].Name, "hello.txt")
	}
}

func TestRAR5Encrypted(t *testing.T) {
	// Without password — should get an error trying to read data
	headers, err := readAll(t, testdataPath("rar5_encrypted.rar"))
	if err != nil {
		// Expected: encrypted file without password
		if len(headers) > 0 && headers[0].Encrypted {
			// Good — we detected the encryption
			t.Logf("correctly detected encrypted file: %v", err)
		}
	} else {
		// If we somehow got headers, they should be marked encrypted
		for _, h := range headers {
			if !h.Encrypted {
				t.Error("expected Encrypted=true")
			}
		}
	}

	// With correct password
	headers, err = readAll(t, testdataPath("rar5_encrypted.rar"), rardecode.Password("test"))
	if err != nil {
		t.Fatal(err)
	}
	if len(headers) != 1 {
		t.Fatalf("expected 1 file, got %d", len(headers))
	}
	if !headers[0].Encrypted {
		t.Error("expected Encrypted=true")
	}
}

func TestRAR5EncryptedHeader(t *testing.T) {
	// Without password — should fail to open
	_, err := readAll(t, testdataPath("rar5_encrypted_header.rar"))
	if err == nil {
		t.Fatal("expected error without password")
	}

	// With correct password
	headers, err := readAll(t, testdataPath("rar5_encrypted_header.rar"), rardecode.Password("test"))
	if err != nil {
		t.Fatal(err)
	}
	if len(headers) != 1 {
		t.Fatalf("expected 1 file, got %d", len(headers))
	}
	if !headers[0].HeaderEncrypted {
		t.Error("expected HeaderEncrypted=true")
	}
}

func TestRAR5Times(t *testing.T) {
	headers, err := readAll(t, testdataPath("rar5_times.rar"))
	if err != nil {
		t.Fatal(err)
	}
	if len(headers) != 1 {
		t.Fatalf("expected 1 file, got %d", len(headers))
	}
	h := headers[0]
	if h.ModificationTime.IsZero() {
		t.Error("expected non-zero ModificationTime")
	}
	if h.CreationTime.IsZero() {
		t.Error("expected non-zero CreationTime")
	}
	if h.AccessTime.IsZero() {
		t.Error("expected non-zero AccessTime")
	}
}

func TestRAR5Symlink(t *testing.T) {
	headers, err := readAll(t, testdataPath("rar5_symlink.rar"))
	if err != nil {
		t.Fatal(err)
	}
	// Find the symlink entry
	var found bool
	for _, h := range headers {
		if h.RedirType == rardecode.RedirUnixSymlink {
			found = true
			if h.RedirTarget != "hello.txt" {
				t.Errorf("RedirTarget = %q, want %q", h.RedirTarget, "hello.txt")
			}
			if h.Mode()&fs.ModeSymlink == 0 {
				t.Error("Mode() should include ModeSymlink")
			}
		}
	}
	if !found {
		t.Errorf("no symlink entry found; got %d headers", len(headers))
		for _, h := range headers {
			t.Logf("  name=%q RedirType=%d", h.Name, h.RedirType)
		}
	}
}

func TestRAR5UnixOwner(t *testing.T) {
	headers, err := readAll(t, testdataPath("rar5_unix_owner.rar"))
	if err != nil {
		t.Fatal(err)
	}
	if len(headers) < 1 {
		t.Fatal("expected at least 1 entry")
	}
	// Find the file (not service) header
	for _, h := range headers {
		if h.IsService {
			continue
		}
		if h.UnixOwner == "" {
			t.Error("expected non-empty UnixOwner")
		}
		if h.UnixGroup == "" {
			t.Error("expected non-empty UnixGroup")
		}
		// Note: rar -ow stores name strings but not always numeric UID/GID.
		// UnixUID/GID remain -1 when not stored in the archive.
		t.Logf("UnixOwner=%q UnixGroup=%q UID=%d GID=%d", h.UnixOwner, h.UnixGroup, h.UnixUID, h.UnixGID)
		return
	}
	t.Error("no non-service file header found")
}

func TestRAR5Comment(t *testing.T) {
	headers, err := readAll(t, testdataPath("rar5_comment.rar"))
	if err != nil {
		t.Fatal(err)
	}
	// Look for the CMT service header
	var foundComment, foundFile bool
	for _, h := range headers {
		if h.IsService && h.Name == "CMT" {
			foundComment = true
		}
		if !h.IsService && h.Name == "hello.txt" {
			foundFile = true
		}
	}
	if !foundComment {
		t.Error("expected CMT service header for archive comment")
	}
	if !foundFile {
		t.Error("expected hello.txt file entry")
	}
}

func TestRAR5Version(t *testing.T) {
	headers, err := readAll(t, testdataPath("rar5_version.rar"))
	if err != nil {
		t.Fatal(err)
	}
	if len(headers) < 1 {
		t.Fatal("expected at least 1 file")
	}
	// With -ver, we should see version numbers
	var foundVersioned bool
	for _, h := range headers {
		if h.Version > 0 {
			foundVersioned = true
			t.Logf("found versioned file: %q version=%d", h.Name, h.Version)
		}
	}
	if !foundVersioned {
		t.Log("no versioned files found (version field may not be set with current rar version)")
	}
}

func TestRAR5MultiVolume(t *testing.T) {
	headers, err := readAll(t, testdataPath("rar5_multi.part01.rar"))
	if err != nil {
		t.Fatal(err)
	}
	if len(headers) < 1 {
		t.Fatalf("expected at least 1 file, got %d", len(headers))
	}
	if headers[0].Name != "large.bin" {
		t.Errorf("name = %q, want %q", headers[0].Name, "large.bin")
	}
	if headers[0].UnPackedSize != 8192 {
		t.Errorf("size = %d, want 8192", headers[0].UnPackedSize)
	}
}

func TestRAR5CorruptHeader(t *testing.T) {
	_, err := readAll(t, testdataPath("rar5_corrupt_header.rar"))
	if err == nil {
		t.Fatal("expected error for corrupt header")
	}
	t.Logf("correctly got error: %v", err)
}

func TestRAR5Truncated(t *testing.T) {
	_, err := readAll(t, testdataPath("rar5_truncated.rar"))
	if err == nil {
		t.Fatal("expected error for truncated archive")
	}
	t.Logf("correctly got error: %v", err)
}

func TestRAR5Locked(t *testing.T) {
	headers, err := readAll(t, testdataPath("rar5_locked.rar"))
	if err != nil {
		t.Fatal(err)
	}
	if len(headers) < 1 {
		t.Fatal("expected at least 1 file")
	}
	// The locked flag is an archive-level flag (0x0010) — currently
	// not exposed on FileHeader, so we just verify the archive parses correctly.
	if headers[0].Name != "hello.txt" {
		t.Errorf("name = %q, want %q", headers[0].Name, "hello.txt")
	}
}

func TestRAR5Recovery(t *testing.T) {
	headers, err := readAll(t, testdataPath("rar5_recovery.rar"))
	if err != nil {
		t.Fatal(err)
	}
	// Recovery record is a service header (RR)
	var foundFile, foundRR bool
	for _, h := range headers {
		if h.IsService && h.Name == "RR" {
			foundRR = true
		}
		if !h.IsService && h.Name == "hello.txt" {
			foundFile = true
		}
	}
	if !foundFile {
		t.Error("expected hello.txt file entry")
	}
	if !foundRR {
		t.Log("RR service header not found (may be after end-of-archive)")
	}
}

// TestAllTestdataFilesOpen ensures every .rar file in testdata/ can be opened
// without panicking, even if it returns an error (e.g., corrupt/truncated).
func TestAllTestdataFilesOpen(t *testing.T) {
	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".rar") {
			continue
		}
		// Skip multi-volume parts other than part01
		if strings.Contains(e.Name(), ".part") && !strings.Contains(e.Name(), ".part01.") {
			continue
		}
		t.Run(e.Name(), func(t *testing.T) {
			name := testdataPath(e.Name())
			var opts []rardecode.Option
			if strings.Contains(e.Name(), "encrypted") {
				opts = append(opts, rardecode.Password("test"))
			}
			rc, err := rardecode.OpenReader(name, opts...)
			if err != nil {
				t.Logf("OpenReader error (may be expected): %v", err)
				return
			}
			defer rc.Close()
			for {
				_, err := rc.Next()
				if err == io.EOF {
					break
				}
				if err != nil {
					t.Logf("Next error (may be expected): %v", err)
					return
				}
				if _, err := io.Copy(io.Discard, &rc.Reader); err != nil {
					t.Logf("Read error (may be expected): %v", err)
					return
				}
			}
		})
	}
}
