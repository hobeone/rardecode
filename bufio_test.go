package rardecode

import (
	"bytes"
	"errors"
	"testing"
)

type errWriter struct{ err error }

func (w errWriter) Write([]byte) (int, error) { return 0, w.err }

func TestBufVolumeReader_WriteToN_PropagatesWriteError(t *testing.T) {
	data := []byte("hello world")
	br := &bufVolumeReader{
		r:   bytes.NewReader(data),
		buf: make([]byte, 64),
	}
	if err := br.fill(); err != nil {
		t.Fatal(err)
	}
	wantErr := errors.New("disk full")
	_, err := br.writeToN(errWriter{wantErr}, int64(len(data)))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
