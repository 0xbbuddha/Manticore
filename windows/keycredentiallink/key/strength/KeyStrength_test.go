package strength_test

import (
	"fmt"
	"testing"

	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink/key/strength"
)

func TestKeyStrengthUnmarshal(t *testing.T) {
	tests := []struct {
		input    []byte
		expected uint32
		name     string
	}{
		{[]byte{0x00, 0x00, 0x00, 0x00}, strength.KeyStrength_Unknown, "Unknown"},
		{[]byte{0x01, 0x00, 0x00, 0x00}, strength.KeyStrength_Weak, "Weak"},
		{[]byte{0x02, 0x00, 0x00, 0x00}, strength.KeyStrength_Normal, "Normal"},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("input: %v", test.input), func(t *testing.T) {
			var ks strength.KeyStrength
			bytesRead, err := ks.Unmarshal(test.input)
			if err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
			if bytesRead != 4 {
				t.Errorf("Expected to read 4 bytes, but read %d", bytesRead)
			}
			if ks.Value != test.expected {
				t.Errorf("Expected value %d, but got %d", test.expected, ks.Value)
			}
			if ks.Name != test.name {
				t.Errorf("Expected name %s, but got %s", test.name, ks.Name)
			}
		})
	}
}

func TestKeyStrengthMarshal(t *testing.T) {
	tests := []struct {
		value    uint32
		expected []byte
	}{
		{strength.KeyStrength_Unknown, []byte{0x00}},
		{strength.KeyStrength_Weak, []byte{0x01}},
		{strength.KeyStrength_Normal, []byte{0x02}},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("value: %d", test.value), func(t *testing.T) {
			ks := strength.KeyStrength{Value: test.value}
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
