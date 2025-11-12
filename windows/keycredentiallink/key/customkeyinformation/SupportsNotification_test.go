package customkeyinformation

import "testing"

func TestSupportsNotification_Unmarshal_Valid(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"True", []byte{1}},
		{"False", []byte{0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sn SupportsNotification
			n, err := sn.Unmarshal(tt.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if n != 1 {
				t.Fatalf("bytes read = %d, want 1", n)
			}
		})
	}
}

func TestSupportsNotification_Unmarshal_Errors(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"TooShort", []byte{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sn SupportsNotification
			if _, err := sn.Unmarshal(tt.input); err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestSupportsNotification_Marshal_Valid(t *testing.T) {
	tests := []struct {
		name     string
		value    SupportsNotification
		expected []byte
	}{
		{"True", SupportsNotification_TRUE, []byte{1}},
		{"False", SupportsNotification_FALSE, []byte{0}},
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
