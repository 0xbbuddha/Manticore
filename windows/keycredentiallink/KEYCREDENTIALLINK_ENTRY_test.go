package keycredentiallink_test

import (
	"encoding/binary"
	"testing"

	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink"
)

// TestKEYCREDENTIALLINK_ENTRY_Unmarshal_BoundsChecks verifies that Unmarshal
// returns an error instead of panicking when fed truncated input at each of
// the three sensitive positions: Length field, Identifier field, and Value
// slice. This mirrors the contract established in #34 for the outer
// KeyCredential type.
func TestKEYCREDENTIALLINK_ENTRY_Unmarshal_BoundsChecks(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{name: "empty", data: []byte{}},
		{name: "length-only-1-byte", data: []byte{0x00}},
		{name: "missing-identifier", data: []byte{0x01, 0x00}}, // Length=1, no identifier
		{
			name: "value-too-short",
			data: func() []byte {
				// Length=0xFFFF, identifier=0x00, zero bytes of value
				b := make([]byte, 3)
				binary.LittleEndian.PutUint16(b[0:2], 0xFFFF)
				b[2] = 0x00
				return b
			}(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("Unmarshal panicked on %q input: %v", tc.name, r)
				}
			}()
			entry := &keycredentiallink.KEYCREDENTIALLINK_ENTRY{}
			_, err := entry.Unmarshal(tc.data)
			if err == nil {
				t.Errorf("Unmarshal(%q) returned nil error; wanted a bounds-check error", tc.name)
			}
		})
	}
}

// TestKEYCREDENTIALLINK_ENTRY_Unmarshal_RoundTrip exercises the happy path:
// a well-formed entry round-trips through Marshal + Unmarshal.
func TestKEYCREDENTIALLINK_ENTRY_Unmarshal_RoundTrip(t *testing.T) {
	original := &keycredentiallink.KEYCREDENTIALLINK_ENTRY{
		Length:     4,
		Identifier: keycredentiallink.KEYCREDENTIALLINK_ENTRY_IDENTIFIER_KeyID,
		Value:      []byte{0xde, 0xad, 0xbe, 0xef},
	}

	data, err := original.Marshal()
	if err != nil {
		t.Fatalf("Marshal returned error: %v", err)
	}

	decoded := &keycredentiallink.KEYCREDENTIALLINK_ENTRY{}
	n, err := decoded.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal returned error: %v", err)
	}
	if n != len(data) {
		t.Errorf("Unmarshal read %d bytes, wanted %d", n, len(data))
	}
	if decoded.Length != original.Length {
		t.Errorf("Length mismatch: got %d, want %d", decoded.Length, original.Length)
	}
	if string(decoded.Value) != string(original.Value) {
		t.Errorf("Value mismatch: got %x, want %x", decoded.Value, original.Value)
	}
}
