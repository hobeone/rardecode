package rardecode

import "testing"

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
