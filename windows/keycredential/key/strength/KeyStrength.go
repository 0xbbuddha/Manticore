package strength

import "encoding/binary"

// KeyStrength specifies the strength of the NGC key.
// See: https://msdn.microsoft.com/en-us/library/mt220496.aspx
type KeyStrength struct {
	Name  string
	Value uint32

	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

const (
	// Key strength is unknown.
	KeyStrength_Unknown uint32 = 0x00

	// Key strength is weak.
	KeyStrength_Weak uint32 = 0x01

	// Key strength is normal.
	KeyStrength_Normal uint32 = 0x02
)

// Unmarshal parses the provided byte slice into the KeyStrength structure.
//
// Parameters:
// - value: A byte slice containing the raw key strength to be parsed.
//
// Returns:
// - The number of bytes read from the data.
// - An error if the parsing fails, otherwise nil.
//
// Note:
// The function expects the byte slice to contain a 4-byte unsigned integer representing the key strength.
// It extracts the key strength value from the byte slice and assigns it to the KeyStrength structure.
func (ks *KeyStrength) Unmarshal(data []byte) (int, error) {
	ks.RawBytes = data[:4]
	ks.RawBytesSize = 4

	ks.Value = binary.LittleEndian.Uint32(data[:4])

	switch ks.Value {
	case KeyStrength_Unknown:
		ks.Name = "Unknown"
	case KeyStrength_Weak:
		ks.Name = "Weak"
	case KeyStrength_Normal:
		ks.Name = "Normal"
	}

	return 4, nil
}

// Marshal returns the raw bytes of the KeyStrength structure.
//
// Returns:
// - A byte slice representing the raw bytes of the KeyStrength structure.
// - An error if the conversion fails.
func (ks *KeyStrength) Marshal() ([]byte, error) {
	ks.RawBytes = []byte{byte(ks.Value)}
	ks.RawBytesSize = 1

	return ks.RawBytes, nil
}
