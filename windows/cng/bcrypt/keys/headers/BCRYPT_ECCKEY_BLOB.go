package headers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// BCRYPT_ECCKEY_BLOB structure is used as a header for an elliptic curve key BLOB in memory.
//
// Source: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob
//
// Remarks:
// This structure is used as a header for a larger buffer. An elliptic curve public key BLOB
// (BCRYPT_ECCPUBLIC_BLOB) has the following format in contiguous memory. The X and Y coordinates
// are unsigned integers encoded in big-endian format.
//
// Syntax:
// BCRYPT_ECCKEY_BLOB
// BYTE X[cbKey] // Big-endian.
// BYTE Y[cbKey] // Big-endian.
//
// An elliptic curve private key BLOB (BCRYPT_ECCPRIVATE_BLOB) has the following format in contiguous
// memory. The X and Y coordinates and d value are unsigned integers encoded in big-endian format.
//
// Syntax:
// BCRYPT_ECCKEY_BLOB
// BYTE X[cbKey] // Big-endian.
// BYTE Y[cbKey] // Big-endian.
// BYTE d[cbKey] // Big-endian.
type BCRYPT_ECCKEY_BLOB struct {
	// The length, in bytes, of the key.
	KeySize uint32
}

// Unmarshal parses the provided byte slice into the BCRYPT_ECCKEY_BLOB structure.
//
// Parameters:
// - value: A byte slice containing the raw elliptic curve key BLOB to be parsed.
//
// Returns:
// - The number of bytes read from the byte slice.
// - An error if the parsing fails, otherwise nil.
//
// Note:
// The function expects the byte slice to follow the elliptic curve key BLOB format, starting with the "ECC1" blob type identifier.
// It extracts the key size from the byte slice and stores it in the BCRYPT_ECCKEY_BLOB structure.
func (b *BCRYPT_ECCKEY_BLOB) Unmarshal(value []byte) (int, error) {
	if len(value) < 4 {
		return 0, errors.New("buffer too small for BCRYPT_ECCKEY_BLOB, header too short (at least 4 bytes are required)")
	}

	b.KeySize = binary.LittleEndian.Uint32(value[:4])

	return 4, nil
}

// Marshal returns the raw bytes of the BCRYPT_ECCKEY_BLOB structure.
//
// Returns:
// - A byte slice representing the raw bytes of the BCRYPT_ECCKEY_BLOB structure.
func (b *BCRYPT_ECCKEY_BLOB) Marshal() ([]byte, error) {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf[:4], b.KeySize)
	return buf, nil
}

// Describe prints the BCRYPT_ECCKEY_BLOB structure to the console.
//
// Parameters:
// - indent: The number of spaces to indent the output.
func (b *BCRYPT_ECCKEY_BLOB) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<\x1b[93mBCRYPT_ECCKEY_BLOB (header)\x1b[0m>\n", indentPrompt)
	fmt.Printf("%s │ \x1b[93mKey Size\x1b[0m: %d\n", indentPrompt, b.KeySize)
	fmt.Printf("%s └───\n", indentPrompt)
}
