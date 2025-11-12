package customkeyinformation

import "testing"

func TestCustomKeyInformationVolumeType_Unmarshal_Valid(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"None", []byte{0x00}},
		{"OSV", []byte{0x01}},
		{"FDV", []byte{0x02}},
		{"RDV", []byte{0x03}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var vt CustomKeyInformationVolumeType
			n, err := vt.Unmarshal(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if n != 1 {
				t.Fatalf("bytes read = %d, want 1", n)
			}
			// Note: Unmarshal has a value receiver; it does not modify vt.
		})
	}
}

func TestCustomKeyInformationVolumeType_Unmarshal_ErrorTooShort(t *testing.T) {
	var vt CustomKeyInformationVolumeType
	if _, err := vt.Unmarshal([]byte{}); err == nil {
		t.Fatalf("expected error for empty input, got nil")
	}
}

func TestCustomKeyInformationVolumeType_Marshal_Valid(t *testing.T) {
	tests := []struct {
		name     string
		value    CustomKeyInformationVolumeType
		expected []byte
	}{
		{"None", CustomKeyInformationVolumeType_None, []byte{0x00}},
		{"OSV", CustomKeyInformationVolumeType_OSV, []byte{0x01}},
		{"FDV", CustomKeyInformationVolumeType_FDV, []byte{0x02}},
		{"RDV", CustomKeyInformationVolumeType_RDV, []byte{0x03}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := tt.value.Marshal()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(out) != 1 || out[0] != tt.expected[0] {
				t.Fatalf("Marshal() = %v, want %v", out, tt.expected)
			}
		})
	}
}

func TestCustomKeyInformationVolumeType_String(t *testing.T) {
	tests := []struct {
		value    CustomKeyInformationVolumeType
		expected string
	}{
		{CustomKeyInformationVolumeType_None, "None"},
		{CustomKeyInformationVolumeType_OSV, "Operating System Volume (OSV)"},
		{CustomKeyInformationVolumeType_FDV, "Fixed Data Volume (FDV)"},
		{CustomKeyInformationVolumeType_RDV, "Removable Data Volume (RDV)"},
		{CustomKeyInformationVolumeType(0xFF), "Unknown"},
	}
	for _, tt := range tests {
		if got := tt.value.String(); got != tt.expected {
			t.Fatalf("String(%#02x) = %q, want %q", uint8(tt.value), got, tt.expected)
		}
	}
}
