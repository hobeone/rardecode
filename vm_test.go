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

func TestShl_ShiftByZero(t *testing.T) {
	v := &vm{m: make([]byte, vmSize+4)}
	shl(v, false, []operand{opI(0xFF), opI(0)})
	if v.fl&flagC != 0 {
		t.Error("carry flag should not be set for shift by 0")
	}
}

func TestShl_ShiftBy32(t *testing.T) {
	v := &vm{m: make([]byte, vmSize+4)}
	shl(v, false, []operand{opI(0xFF), opI(32)})
	if v.fl&flagZ == 0 {
		t.Error("zero flag should be set for shift >= 32")
	}
}

func TestShr_ShiftByZero(t *testing.T) {
	v := &vm{m: make([]byte, vmSize+4)}
	shr(v, false, []operand{opI(0xFF), opI(0)})
	if v.fl&flagC != 0 {
		t.Error("carry flag should not be set for shift by 0")
	}
}

func TestSar_ShiftBy32_Negative(t *testing.T) {
	v := &vm{m: make([]byte, vmSize+4)}
	sar(v, false, []operand{opI(0x80000000), opI(32)})
	if v.fl&flagS == 0 {
		t.Error("sign flag should be set for negative sar by 32")
	}
}

func TestSar_ShiftBy32_Positive(t *testing.T) {
	v := &vm{m: make([]byte, vmSize+4)}
	sar(v, false, []operand{opI(0x7FFFFFFF), opI(32)})
	if v.fl&flagZ == 0 {
		t.Error("zero flag should be set for positive sar by 32")
	}
}
