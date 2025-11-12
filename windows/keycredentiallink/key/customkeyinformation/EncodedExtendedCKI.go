package customkeyinformation

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// EncodedExtendedCKI represents the EncodedExtendedCKI structure.
//
// Spec: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/b2c0cb9b-e49e-4907-9235-f9fd7eee8c13
//
// Fields:
// - Version (1 byte): MUST be 0.
// - Size (1 byte): Size in bytes of the Data field.
// - Data (variable): CBOR-encoded blob, length == Size.
type EncodedExtendedCKI struct {
	// Version MUST be 0
	Version uint8

	// Size of Data in bytes
	Size uint8

	// CBOR-encoded blob whose length is specified by Size
	Data []byte
}

// Unmarshal parses EncodedExtendedCKI from the provided buffer.
// Returns number of bytes read.
func (e *EncodedExtendedCKI) Unmarshal(data []byte) (int, error) {
	if len(data) < 2 {
		return 0, fmt.Errorf("invalid data length: %d", len(data))
	}

	e.Version = data[0]
	if e.Version != 0 {
		return 0, fmt.Errorf("invalid EncodedExtendedCKI version: %d", e.Version)
	}

	e.Size = data[1]

	total := 2 + int(e.Size)
	if len(data) < total {
		return 0, fmt.Errorf("buffer too short for Data: have %d, need %d", len(data), total)
	}

	if e.Size > 0 {
		e.Data = make([]byte, e.Size)
		copy(e.Data, data[2:total])
	} else {
		e.Data = nil
	}

	return total, nil
}

// Marshal serializes the structure to bytes.
func (e *EncodedExtendedCKI) Marshal() ([]byte, error) {
	if len(e.Data) > 0xFF {
		return nil, fmt.Errorf("data too long: %d bytes (max 255)", len(e.Data))
	}
	e.Version = 0
	e.Size = uint8(len(e.Data))

	out := make([]byte, 2+len(e.Data))
	out[0] = e.Version
	out[1] = e.Size
	copy(out[2:], e.Data)

	return out, nil
}

// Describe prints a human-readable description.
func (e *EncodedExtendedCKI) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<\x1b[93mEncodedExtendedCKI\x1b[0m>\n", indentPrompt)
	fmt.Printf("%s │ \x1b[93mVersion\x1b[0m: %d\n", indentPrompt, e.Version)
	fmt.Printf("%s │ \x1b[93mSize\x1b[0m: %d\n", indentPrompt, e.Size)
	if len(e.Data) > 0 {
		fmt.Printf("%s │ \x1b[93mData\x1b[0m: %s\n", indentPrompt, hex.EncodeToString(e.Data))
	} else {
		fmt.Printf("%s │ \x1b[93mData\x1b[0m: None\n", indentPrompt)
	}
	fmt.Printf("%s └───\n", indentPrompt)
}
