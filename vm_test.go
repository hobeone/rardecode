package rardecode

import "testing"

func TestPush_StackUnderflow(t *testing.T) {
	v := &vm{m: make([]byte, vmSize+4)}
	v.r[7] = 0
	push(v, false, []operand{opI(42)})
	if v.ip != 0xFFFFFFFF {
		t.Error("push with empty stack should trigger program end")
	}
}

func TestCall_StackUnderflow(t *testing.T) {
	v := &vm{m: make([]byte, vmSize+4)}
	v.r[7] = 2
	call(v, false, []operand{opI(100)})
	if v.ip != 0xFFFFFFFF {
		t.Error("call with insufficient stack should trigger program end")
	}
}

func TestPushf_StackUnderflow(t *testing.T) {
	v := &vm{m: make([]byte, vmSize+4)}
	v.r[7] = 0
	pushf(v, false, nil)
	if v.ip != 0xFFFFFFFF {
		t.Error("pushf with empty stack should trigger program end")
	}
}
