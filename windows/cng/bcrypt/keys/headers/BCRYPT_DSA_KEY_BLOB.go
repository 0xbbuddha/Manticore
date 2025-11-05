package headers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// BCRYPT_DSA_KEY_BLOB structure is used to represent the header of a DSA key BLOB in memory.
//
// Source: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_dsa_key_blob
//
// This structure is used as the header for buffers that store DSA public/private key material.
type BCRYPT_DSA_KEY_BLOB struct {
	// The length, in bytes, of the key.
	CbKey uint32

	// The counter value used during the generation of the key.
	Count [4]byte

	// The seed used for key generation.
	Seed [20]byte

	// The DSA q parameter.
	Q [20]byte
}

// Unmarshal parses the provided byte slice into the BCRYPT_DSA_KEY_BLOB structure.
func (b *BCRYPT_DSA_KEY_BLOB) Unmarshal(value []byte) (int, error) {
	if len(value) < 4+4+20+20 {
		return 0, errors.New("buffer too small for BCRYPT_DSA_KEY_BLOB, 48 bytes required")
	}
	offset := 0
	b.CbKey = binary.LittleEndian.Uint32(value[offset : offset+4])
	offset += 4
	copy(b.Count[:], value[offset:offset+4])
	offset += 4
	copy(b.Seed[:], value[offset:offset+20])
	offset += 20
	copy(b.Q[:], value[offset:offset+20])
	offset += 20
	return offset, nil
}

// Marshal returns the raw bytes of the BCRYPT_DSA_KEY_BLOB structure.
func (b *BCRYPT_DSA_KEY_BLOB) Marshal() ([]byte, error) {
	buf := make([]byte, 4+4+20+20)
	offset := 0
	binary.LittleEndian.PutUint32(buf[offset:offset+4], b.CbKey)
	offset += 4
	copy(buf[offset:offset+4], b.Count[:])
	offset += 4
	copy(buf[offset:offset+20], b.Seed[:])
	offset += 20
	copy(buf[offset:offset+20], b.Q[:])
	offset += 20
	return buf, nil
}

// Describe prints the BCRYPT_DSA_KEY_BLOB structure to the console.
func (b *BCRYPT_DSA_KEY_BLOB) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<\x1b[93mBCRYPT_DSA_KEY_BLOB (header)\x1b[0m>\n", indentPrompt)
	fmt.Printf("%s │ \x1b[93mKey Size\x1b[0m : %d\n", indentPrompt, b.CbKey)
	fmt.Printf("%s │ \x1b[93mCount\x1b[0m    : % 02x\n", indentPrompt, b.Count)
	fmt.Printf("%s │ \x1b[93mSeed\x1b[0m     : % 02x\n", indentPrompt, b.Seed)
	fmt.Printf("%s │ \x1b[93mQ\x1b[0m        : % 02x\n", indentPrompt, b.Q)
	fmt.Printf("%s └───\n", indentPrompt)
}
