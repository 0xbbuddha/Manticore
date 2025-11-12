package strength

import (
	"encoding/binary"
	"fmt"
)

// KeyStrength specifies the strength of the NGC key.
// See: https://msdn.microsoft.com/en-us/library/mt220496.aspx
type KeyStrength uint32

const (
	// Key strength is unknown.
	KeyStrength_Unknown KeyStrength = 0x00

	// Key strength is weak.
	KeyStrength_Weak KeyStrength = 0x01

	// Key strength is normal.
	KeyStrength_Normal KeyStrength = 0x02
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
	if len(data) < 4 {
		return 0, fmt.Errorf("invalid data length: %d", len(data))
	}

	*ks = KeyStrength(binary.LittleEndian.Uint32(data[:4]))

	return 4, nil
}

// Marshal returns the raw bytes of the KeyStrength structure.
//
// Returns:
// - A byte slice representing the raw bytes of the KeyStrength structure.
// - An error if the conversion fails.
func (ks *KeyStrength) Marshal() ([]byte, error) {
	marshalledData := make([]byte, 4)
	binary.LittleEndian.PutUint32(marshalledData, uint32(*ks))
	return marshalledData, nil
}

func (ks KeyStrength) String() string {
	switch ks {
	case KeyStrength_Unknown:
		return "Unknown"
	case KeyStrength_Weak:
		return "Weak"
	case KeyStrength_Normal:
		return "Normal"
	}
	return "Unknown"
}
