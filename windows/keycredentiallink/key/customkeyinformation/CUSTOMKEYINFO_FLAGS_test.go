package customkeyinformation

import "testing"

func TestCUSTOMKEYINFO_FLAGS_Unmarshal_Valid(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"None", []byte{0x00}},
		{"Attestation", []byte{0x01}},
		{"MFANotUsed", []byte{0x02}},
		{"BothBits", []byte{0x03}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var f CUSTOMKEYINFO_FLAGS
			n, err := f.Unmarshal(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if n != 1 {
				t.Fatalf("bytes read = %d, want 1", n)
			}
		})
	}
}

func TestCUSTOMKEYINFO_FLAGS_Unmarshal_Errors(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"TooShort", []byte{}},
		{"InvalidBit", []byte{0x04}},
		{"InvalidHighBits", []byte{0x80}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var f CUSTOMKEYINFO_FLAGS
			if _, err := f.Unmarshal(tt.input); err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestCUSTOMKEYINFO_FLAGS_String(t *testing.T) {
	tests := []struct {
		flag     CUSTOMKEYINFO_FLAGS
		expected string
	}{
		{CUSTOMKEYINFO_FLAGS_None, "None"},
		{CUSTOMKEYINFO_FLAGS_Attestation, "Attestation"},
		{CUSTOMKEYINFO_FLAGS_MFANotUsed, "MFA not used"},
		{CUSTOMKEYINFO_FLAGS(0x03), "Unknown"}, // combo not mapped explicitly
		{CUSTOMKEYINFO_FLAGS(0xFF), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.flag.String(); got != tt.expected {
			t.Fatalf("String(%#02x) = %q, want %q", uint8(tt.flag), got, tt.expected)
		}
	}
}
