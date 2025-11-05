package blob

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// BCRYPT_KEY_BLOB structure is used as a header for a key BLOB in memory.
//
// See:
// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_key_blob
type BCRYPT_KEY_BLOB struct {
	// Specifies the type of key this BLOB represents. The possible values for this member
	// depend on the type of BLOB this structure represents.
	Magic uint32
}

// Unmarshal parses the provided byte slice into the BCRYPT_KEY_BLOB structure.
//
// Parameters:
// - value: A byte slice containing the raw key BLOB to be parsed.
//
// Returns:
// - The number of bytes read from the byte slice.
// - An error if the parsing fails, otherwise nil.
//
// Note:
// The function expects the byte slice to follow the key BLOB format, starting with the "KEY1" blob type identifier.
// It extracts the key type from the byte slice and stores it in the BCRYPT_KEY_BLOB structure.
func (b *BCRYPT_KEY_BLOB) Unmarshal(value []byte) (int, error) {
	if len(value) < 4 {
		return 0, errors.New("buffer too small for BCRYPT_KEY_BLOB, header too short (at least 4 bytes are required)")
	}

	b.Magic = binary.LittleEndian.Uint32(value[:4])

	return 4, nil
}

// Marshal returns the raw bytes of the BCRYPT_KEY_BLOB structure.
//
// Returns:
// - A byte slice representing the raw bytes of the BCRYPT_KEY_BLOB structure.
func (b *BCRYPT_KEY_BLOB) Marshal() ([]byte, error) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf[:4], b.Magic)
	return buf, nil
}

// String returns a string representation of the BCRYPT_KEY_BLOB structure.
//
// Returns:
// - A string representing the BCRYPT_KEY_BLOB structure.
func (b *BCRYPT_KEY_BLOB) String() string {
	return fmt.Sprintf("BCRYPT_KEY_BLOB: Magic=0x%08x", b.Magic)
}

// Equal returns true if the BCRYPT_KEY_BLOB structure is equal to the other BCRYPT_KEY_BLOB structure.
//
// Parameters:
// - other: The other BCRYPT_KEY_BLOB structure to compare to.
//
// Returns:
// - True if the BCRYPT_KEY_BLOB structure is equal to the other BCRYPT_KEY_BLOB structure, otherwise false.
func (b *BCRYPT_KEY_BLOB) Equal(other *BCRYPT_KEY_BLOB) bool {
	return b.Magic == other.Magic
}
