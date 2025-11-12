package customkeyinformation

import (
	"encoding/hex"
	"fmt"
)

// Reserved represents the Reserved structure.
//
// See: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/701a55dc-d062-4032-a2da-dbdfc384c8cf
type Reserved [10]byte

// Unmarshal parses the provided byte slice into the Reserved structure.
//
// Parameters:
// - data: A byte slice containing the raw reserved to be parsed.
//
// Returns:
// - The number of bytes read from the data.
// - An error if the parsing fails, otherwise nil.
//
// Note:
// The function expects the byte slice to contain 10 bytes.
// It copies the 10 bytes from the byte slice to the Reserved structure.
func (r *Reserved) Unmarshal(data []byte) (int, error) {
	if len(data) < 10 {
		return 0, fmt.Errorf("invalid data length: %d", len(data))
	}

	copy(r[:], data[:10])

	return 10, nil
}

// Marshal returns the raw bytes of the Reserved structure.
//
// Returns:
// - A byte slice representing the raw bytes of the Reserved structure.
// - An error if the conversion fails.
func (r *Reserved) Marshal() ([]byte, error) {
	return r[:], nil
}

// String returns a string representation of the Reserved.
//
// Returns:
// - A string representing the Reserved.
func (r *Reserved) String() string {
	return hex.EncodeToString(r[:])
}
