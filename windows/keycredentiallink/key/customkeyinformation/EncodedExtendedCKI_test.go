package customkeyinformation

import (
	"bytes"
	"testing"
)

func TestEncodedExtendedCKI_Unmarshal_Valid(t *testing.T) {
	input := []byte{0x00, 0x03, 0xDE, 0xAD, 0xBE}
	var e EncodedExtendedCKI
	n, err := e.Unmarshal(input)
	if err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if n != len(input) {
		t.Fatalf("bytes read = %d, want %d", n, len(input))
	}
	if e.Version != 0 {
		t.Fatalf("Version = %d, want 0", e.Version)
	}
	if e.Size != 3 {
		t.Fatalf("Size = %d, want 3", e.Size)
	}
	if !bytes.Equal(e.Data, []byte{0xDE, 0xAD, 0xBE}) {
		t.Fatalf("Data = %v, want %v", e.Data, []byte{0xDE, 0xAD, 0xBE})
	}
}

func TestEncodedExtendedCKI_Unmarshal_ZeroSize(t *testing.T) {
	input := []byte{0x00, 0x00}
	var e EncodedExtendedCKI
	n, err := e.Unmarshal(input)
	if err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if n != len(input) {
		t.Fatalf("bytes read = %d, want %d", n, len(input))
	}
	if e.Version != 0 {
		t.Fatalf("Version = %d, want 0", e.Version)
	}
	if e.Size != 0 {
		t.Fatalf("Size = %d, want 0", e.Size)
	}
	if e.Data != nil {
		t.Fatalf("Data = %v, want nil", e.Data)
	}
}

func TestEncodedExtendedCKI_Unmarshal_Errors(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
	}{
		{"TooShort", []byte{0x00}},
		{"BadVersion", []byte{0x01, 0x00}},
		{"SizeExceedsBuffer", []byte{0x00, 0x04, 0xAA, 0xBB, 0xCC}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var e EncodedExtendedCKI
			if _, err := e.Unmarshal(tc.in); err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestEncodedExtendedCKI_Marshal_Valid(t *testing.T) {
	e := EncodedExtendedCKI{
		Data: []byte{0xCA, 0xFE, 0xBA, 0xBE},
	}
	out, err := e.Marshal()
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	want := append([]byte{0x00, 0x04}, []byte{0xCA, 0xFE, 0xBA, 0xBE}...)
	if !bytes.Equal(out, want) {
		t.Fatalf("Marshal = %v, want %v", out, want)
	}
	if e.Version != 0 {
		t.Fatalf("Version after Marshal = %d, want 0", e.Version)
	}
	if e.Size != 4 {
		t.Fatalf("Size after Marshal = %d, want 4", e.Size)
	}
}

func TestEncodedExtendedCKI_Marshal_DataTooLong(t *testing.T) {
	e := EncodedExtendedCKI{
		Data: make([]byte, 256),
	}
	if _, err := e.Marshal(); err == nil {
		t.Fatalf("expected error for data length > 255, got nil")
	}
}

func TestEncodedExtendedCKI_RoundTrip(t *testing.T) {
	original := EncodedExtendedCKI{
		Data: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
	}
	blob, err := original.Marshal()
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}
	var parsed EncodedExtendedCKI
	if _, err := parsed.Unmarshal(blob); err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if parsed.Version != 0 || parsed.Size != uint8(len(original.Data)) {
		t.Fatalf("parsed header mismatch: version=%d size=%d", parsed.Version, parsed.Size)
	}
	if !bytes.Equal(parsed.Data, original.Data) {
		t.Fatalf("parsed data mismatch: %v vs %v", parsed.Data, original.Data)
	}
}
