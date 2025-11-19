package class_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/network/llmnr/class"
)

func TestIsUnicastPreferred(t *testing.T) {
	tests := []struct {
		val      class.Class
		expected bool
	}{
		{class.ClassIN, false},
		{class.ClassIN | class.ClassUnicastPreferred, true},
		{class.ClassANY, false},
		{class.ClassANY | class.ClassUnicastPreferred, true},
		{class.ClassUnicastPreferred, true},
	}
	for _, tt := range tests {
		got := tt.val.IsUnicastPreferred()
		if got != tt.expected {
			t.Errorf("IsUnicastPreferred() for %v = %v; want %v", tt.val, got, tt.expected)
		}
	}
}

func TestBaseClass(t *testing.T) {
	c := class.ClassIN | class.ClassUnicastPreferred
	if c.BaseClass() != class.ClassIN {
		t.Errorf("BaseClass() = %v; want %v", c.BaseClass(), class.ClassIN)
	}
	noFlag := class.ClassCH
	if noFlag.BaseClass() != class.ClassCH {
		t.Errorf("BaseClass() = %v; want %v", noFlag.BaseClass(), class.ClassCH)
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	allVals := []class.Class{
		class.ClassIN,
		class.ClassIN | class.ClassUnicastPreferred,
		class.ClassCS,
		class.ClassCH,
		class.ClassANY,
		class.ClassNONE,
	}
	for _, c := range allVals {
		marshalled, err := c.Marshal()
		if err != nil {
			t.Fatalf("Marshal(%v) failed: %v", c, err)
		}

		var decoded class.Class
		n, err := decoded.Unmarshal(marshalled)
		if err != nil {
			t.Fatalf("Unmarshal(%v) failed: %v", marshalled, err)
		}

		if n != 2 {
			t.Errorf("Unmarshal() read %d bytes; want 2", n)
		}

		if decoded != c {
			t.Errorf("Unmarshal(Marshal(%v)) = %v; want %v", c, decoded, c)
		}
	}
}

func TestUnmarshalInvalidLength(t *testing.T) {
	var c class.Class
	_, err := c.Unmarshal([]byte{1})
	if err == nil {
		t.Error("Unmarshal should fail on bad input length, got nil error")
	}
}

func TestString(t *testing.T) {
	tests := []struct {
		val      class.Class
		expected string
	}{
		{class.ClassIN, "IN"},
		{class.ClassIN | class.ClassUnicastPreferred, "UNICAST|IN"},
		{class.ClassCH, "CH"},
		{class.ClassCH | class.ClassUnicastPreferred, "UNICAST|CH"},
		{42, "Unknown"},
		{class.ClassUnicastPreferred | 42, "UNICAST|Unknown"},
	}
	for _, tt := range tests {
		got := tt.val.String()
		if got != tt.expected {
			t.Errorf("String() = %q; want %q for 0x%X", got, tt.expected, uint16(tt.val))
		}
	}
}
