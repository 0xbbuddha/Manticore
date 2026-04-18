package header_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/network/llmnr/message/header"
)

func TestIsQueryAndIsResponse(t *testing.T) {
	var flag header.Flags

	flag = 0 // QR not set
	if !flag.IsQuery() {
		t.Errorf("Flags(0) should be query (IsQuery == true)")
	}
	if flag.IsResponse() {
		t.Errorf("Flags(0) should not be response (IsResponse == false)")
	}

	flag = header.FlagQR // QR set
	if flag.IsQuery() {
		t.Errorf("Flags(QR) should not be query (IsQuery == false)")
	}
	if !flag.IsResponse() {
		t.Errorf("Flags(QR) should be response (IsResponse == true)")
	}
}

func TestIsConflict(t *testing.T) {
	var f header.Flags = 0
	if f.IsConflict() {
		t.Error("Flags(0) should not have conflict")
	}
	f = header.FlagC
	if !f.IsConflict() {
		t.Error("Flags(C) should have conflict")
	}
}

func TestIsTruncation(t *testing.T) {
	var f header.Flags = 0
	if f.IsTruncation() {
		t.Error("Flags(0) should not have truncation")
	}
	f = header.FlagTC
	if !f.IsTruncation() {
		t.Error("Flags(TC) should have truncation")
	}
}

func TestIsTentative(t *testing.T) {
	var f header.Flags = 0
	if f.IsTentative() {
		t.Error("Flags(0) should not be tentative")
	}
	f = header.FlagT
	if !f.IsTentative() {
		t.Error("Flags(T) should be tentative")
	}
}

func TestFlagsMarshalUnmarshal(t *testing.T) {
	testVals := []header.Flags{
		0,
		header.FlagQR,
		header.FlagC,
		header.FlagTC,
		header.FlagT,
		header.FlagQR | header.FlagC,
		header.FlagQR | header.FlagTC | header.FlagT,
		header.FlagQR | header.FlagOP | header.FlagC | header.FlagTC | header.FlagT,
	}
	for _, orig := range testVals {
		cpy := orig
		b, err := cpy.Marshal()
		if err != nil {
			t.Fatalf("Marshal(%#v) failed: %v", orig, err)
		}
		if len(b) != 2 {
			t.Errorf("Marshal(%#v) = %v (len %d), want 2 bytes", orig, b, len(b))
		}

		var decoded header.Flags
		n, err := decoded.Unmarshal(b)
		if err != nil {
			t.Fatalf("Unmarshal(%v) failed: %v", b, err)
		}
		if n != 2 {
			t.Errorf("Unmarshal() read %d bytes; want 2", n)
		}
		if decoded != orig {
			t.Errorf("Unmarshal(Marshal(%#v)) = %#v; want %#v", orig, decoded, orig)
		}
	}
}

func TestFlagsUnmarshalInvalidLength(t *testing.T) {
	var f header.Flags
	_, err := f.Unmarshal([]byte{1})
	if err == nil {
		t.Error("Unmarshal should fail on input of 1 byte (should error), got nil error")
	}
	_, err = f.Unmarshal([]byte{0, 1, 2})
	if err == nil {
		t.Error("Unmarshal should fail on input of 3 bytes (should error), got nil error")
	}
}

func TestFlagsString(t *testing.T) {
	tests := []struct {
		flags    header.Flags
		expected string
	}{
		// Query messages (QR bit clear) must not emit "QR".
		{0, ""},
		{header.FlagC, "C"},
		{header.FlagTC, "TC"},
		{header.FlagT, "T"},
		// Response messages (QR bit set) emit "QR".
		{header.FlagQR, "QR"},
		{header.FlagQR | header.FlagC, "QR|C"},
		{header.FlagQR | header.FlagTC | header.FlagT, "QR|TC|T"},
		// FlagOP is not rendered as a label by String(); OPCODE is a 4-bit field,
		// not a single-bit flag, and is deliberately not surfaced here.
		{header.FlagQR | header.FlagOP | header.FlagC | header.FlagTC | header.FlagT, "QR|C|TC|T"},
	}
	for _, tt := range tests {
		got := tt.flags.String()
		if got != tt.expected {
			t.Errorf("Flags.String() = %q, want %q for value %#x", got, tt.expected, uint16(tt.flags))
		}
	}
}
