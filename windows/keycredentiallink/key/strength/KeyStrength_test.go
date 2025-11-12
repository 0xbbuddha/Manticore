package strength_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink/key/strength"
)

func TestKeyStrength_Unmarshal_Valid(t *testing.T) {
	tests := []struct {
		input    []byte
		expected strength.KeyStrength
		name     string
	}{
		{[]byte{0x00, 0x00, 0x00, 0x00}, strength.KeyStrength_Unknown, "Unknown"},
		{[]byte{0x01, 0x00, 0x00, 0x00}, strength.KeyStrength_Weak, "Weak"},
		{[]byte{0x02, 0x00, 0x00, 0x00}, strength.KeyStrength_Normal, "Normal"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var ks strength.KeyStrength
			bytesRead, err := ks.Unmarshal(test.input)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if bytesRead != 4 {
				t.Errorf("Expected to read 4 bytes, but read %d", bytesRead)
			}
			if uint32(ks) != uint32(test.expected) {
				t.Errorf("Expected value %d, but got %d", uint32(test.expected), uint32(ks))
			}
			if ks.String() != test.name {
				t.Errorf("Expected name %s, but got %s", test.name, ks.String())
			}
		})
	}
}

func TestKeyStrength_Unmarshal_UnknownValue(t *testing.T) {
	// Value 0xFF is not defined; expect String() to fall back to "Unknown"
	input := []byte{0xFF, 0x00, 0x00, 0x00}
	var ks strength.KeyStrength
	bytesRead, err := ks.Unmarshal(input)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if bytesRead != 4 {
		t.Fatalf("Expected to read 4 bytes, but read %d", bytesRead)
	}
	if uint32(ks) != 0xFF {
		t.Fatalf("Expected value 255, but got %d", uint32(ks))
	}
	if ks.String() != "Unknown" {
		t.Fatalf("Expected name %q for unknown value, but got %q", "Unknown", ks.String())
	}
}

func TestKeyStrength_Unmarshal_ErrorTooShort(t *testing.T) {
	var ks strength.KeyStrength
	if _, err := ks.Unmarshal([]byte{0x01, 0x00, 0x00}); err == nil {
		t.Fatalf("expected error for too short input, got nil")
	}
}

func TestKeyStrength_Marshal_Valid(t *testing.T) {
	tests := []struct {
		value    strength.KeyStrength
		expected []byte
	}{
		{strength.KeyStrength_Unknown, []byte{0x00, 0x00, 0x00, 0x00}},
		{strength.KeyStrength_Weak, []byte{0x01, 0x00, 0x00, 0x00}},
		{strength.KeyStrength_Normal, []byte{0x02, 0x00, 0x00, 0x00}},
	}

	for _, test := range tests {
		t.Run(test.value.String(), func(t *testing.T) {
			ks := test.value
			result, err := ks.Marshal()
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if len(result) != len(test.expected) {
				t.Errorf("Expected %d bytes, but got %d", len(test.expected), len(result))
			}
			for i := range result {
				if result[i] != test.expected[i] {
					t.Errorf("Byte %d: expected %02x, but got %02x", i, test.expected[i], result[i])
				}
			}
		})
	}
}
