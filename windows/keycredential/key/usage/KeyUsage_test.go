package usage_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/TheManticoreProject/Manticore/windows/keycredential/key/usage"
)

func TestKeyUsage_Unmarshal(t *testing.T) {
	tests := []struct {
		input    byte
		expected usage.KeyUsage
	}{
		{0x00, usage.KeyUsage{Value: 0x00, RawBytes: []byte{0x00}, RawBytesSize: 1}},
		{0x01, usage.KeyUsage{Value: 0x01, RawBytes: []byte{0x01}, RawBytesSize: 1}},
		{0x02, usage.KeyUsage{Value: 0x02, RawBytes: []byte{0x02}, RawBytesSize: 1}},
		{0x03, usage.KeyUsage{Value: 0x03, RawBytes: []byte{0x03}, RawBytesSize: 1}},
		{0x04, usage.KeyUsage{Value: 0x04, RawBytes: []byte{0x04}, RawBytesSize: 1}},
		{0x07, usage.KeyUsage{Value: 0x07, RawBytes: []byte{0x07}, RawBytesSize: 1}},
		{0x08, usage.KeyUsage{Value: 0x08, RawBytes: []byte{0x08}, RawBytesSize: 1}},
		{0x09, usage.KeyUsage{Value: 0x09, RawBytes: []byte{0x09}, RawBytesSize: 1}},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("input=%x", tt.input), func(t *testing.T) {
			var ku usage.KeyUsage
			ku.Unmarshal([]byte{tt.input})
			if ku.Value != tt.expected.Value || !bytes.Equal(ku.RawBytes, tt.expected.RawBytes) || ku.RawBytesSize != tt.expected.RawBytesSize {
				t.Errorf("got %+v, want %+v", ku, tt.expected)
			}
		})
	}
}

func TestKeyUsage_Marshal(t *testing.T) {
	tests := []struct {
		input    usage.KeyUsage
		expected []byte
	}{
		{usage.KeyUsage{Value: 0x00}, []byte{0x00}},
		{usage.KeyUsage{Value: 0x01}, []byte{0x01}},
		{usage.KeyUsage{Value: 0x02}, []byte{0x02}},
		{usage.KeyUsage{Value: 0x03}, []byte{0x03}},
		{usage.KeyUsage{Value: 0x04}, []byte{0x04}},
		{usage.KeyUsage{Value: 0x07}, []byte{0x07}},
		{usage.KeyUsage{Value: 0x08}, []byte{0x08}},
		{usage.KeyUsage{Value: 0x09}, []byte{0x09}},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("input=%x", tt.input.Value), func(t *testing.T) {
			data, err := tt.input.Marshal()
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !bytes.Equal(data, tt.expected) {
				t.Errorf("got %x, want %x", data, tt.expected)
			}
		})
	}
}

func TestKeyUsage_MarshalUnmarshal(t *testing.T) {
	tests := []struct {
		value uint8
	}{
		{0x00},
		{0x01},
		{0x02},
		{0x03},
		{0x04},
		{0x07},
		{0x08},
		{0x09},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("value=%x", tt.value), func(t *testing.T) {
			original := usage.KeyUsage{Value: tt.value}

			// Marshal
			data, err := original.Marshal()
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}

			// Unmarshal
			var unmarshaled usage.KeyUsage
			_, err = unmarshaled.Unmarshal(data)
			if err != nil {
				t.Fatalf("Unmarshal failed: %v", err)
			}

			// Compare
			if original.Value != unmarshaled.Value {
				t.Errorf("value mismatch: got %x, want %x", unmarshaled.Value, original.Value)
			}
			if !bytes.Equal(unmarshaled.RawBytes, data) {
				t.Errorf("raw bytes mismatch: got %x, want %x", unmarshaled.RawBytes, data)
			}
			if unmarshaled.RawBytesSize != uint8(len(data)) {
				t.Errorf("raw bytes size mismatch: got %d, want %d", unmarshaled.RawBytesSize, len(data))
			}
		})
	}
}
