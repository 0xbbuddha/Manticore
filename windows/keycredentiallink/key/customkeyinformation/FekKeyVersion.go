package customkeyinformation

import "fmt"

type FekKeyVersion uint8

const (
	FekKeyVersion_1 FekKeyVersion = 0x01
)

// Marshal returns the raw bytes of the FekKeyVersion structure.
//
// Returns:
// - A byte slice representing the raw bytes of the FekKeyVersion structure.
// - An error if the conversion fails.
func (fv FekKeyVersion) Marshal() ([]byte, error) {
	return []byte{uint8(fv)}, nil
}

// Unmarshal parses the provided byte slice into the FekKeyVersion structure.
//
// Parameters:
// - data: A byte slice containing the raw FekKeyVersion to be parsed.
//
// Returns:
// - The number of bytes read from the data.
// - An error if the parsing fails, otherwise nil.
func (fv *FekKeyVersion) Unmarshal(data []byte) (int, error) {
	if len(data) < 1 {
		return 0, fmt.Errorf("invalid data length: %d", len(data))
	}

	*fv = FekKeyVersion(data[0])

	return 1, nil
}

// String returns a string representation of the FekKeyVersion.
//
// Returns:
// - A string representing the FekKeyVersion.
func (fv FekKeyVersion) String() string {
	return fmt.Sprintf("0x%02x", uint8(fv))
}
