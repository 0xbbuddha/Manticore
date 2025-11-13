package keys

import (
	"errors"
	"fmt"
	"strings"

	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/blob"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/headers"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/magic"
)

type BCRYPT_ECC_PUBLIC_KEY struct {
	// Magic is the magic signature of the key.
	Magic magic.BCRYPT_KEY_BLOB

	// Header is the header of the key.
	Header headers.BCRYPT_ECC_KEY_BLOB

	// Content is the content of the key.
	Content blob.BCRYPT_ECC_PUBLIC_BLOB
}

// Unmarshal parses the provided byte slice into the BCRYPT_ECC_PUBLIC_KEY structure.
//
// Parameters:
// - value: A byte slice containing the raw ECC public key to be parsed.
//
// Returns:
// - The number of bytes read from the byte slice.
// - An error if the parsing fails, otherwise nil.
//
// Note:
// The function expects the byte slice to follow the ECC public key format, starting with the BCRYPT_ECC_KEY_BLOB header.
// It extracts the X and Y big-endian values from the byte slice and stores them in the BCRYPT_ECC_PUBLIC_KEY structure.
func (k *BCRYPT_ECC_PUBLIC_KEY) Unmarshal(value []byte) (int, error) {
	// Need at least 8 bytes for magic (4) + header (4)
	if len(value) < 8 {
		return 0, errors.New("buffer too small for BCRYPT_ECC_PUBLIC_KEY, header too short (at least 8 bytes are required)")
	}

	bytesRead := 0

	// Unmarshalling magic
	bytesReadMagic, err := k.Magic.Unmarshal(value[:4])
	if err != nil {
		return 0, err
	}
	if !isValidECCPublicMagic(k.Magic.Magic) {
		return 0, fmt.Errorf("invalid ECC public key magic: 0x%08x", k.Magic.Magic)
	}
	bytesRead += bytesReadMagic

	// Unmarshalling header
	bytesReadHeader, err := k.Header.Unmarshal(value[bytesRead:])
	if err != nil {
		return 0, err
	}
	bytesRead += bytesReadHeader

	// Unmarshalling content
	bytesReadContent, err := k.Content.Unmarshal(k.Header, value[bytesRead:])
	if err != nil {
		return 0, err
	}
	bytesRead += bytesReadContent

	return bytesRead, nil
}

// Marshal returns the raw bytes of the BCRYPT_ECC_PUBLIC_KEY structure.
//
// Returns:
// - A byte slice representing the raw bytes of the BCRYPT_ECC_PUBLIC_KEY structure.
func (k *BCRYPT_ECC_PUBLIC_KEY) Marshal() ([]byte, error) {
	if !isValidECCPublicMagic(k.Magic.Magic) {
		return nil, fmt.Errorf("invalid ECC public key magic for marshal: 0x%08x", k.Magic.Magic)
	}

	marshalledData := []byte{}

	// Marshalling magic (kept as-is; caller must select appropriate curve/type magic)
	marshalledMagic, err := k.Magic.Marshal()
	if err != nil {
		return nil, err
	}
	marshalledData = append(marshalledData, marshalledMagic...)

	// Marshalling header
	marshalledHeader, err := k.Header.Marshal()
	if err != nil {
		return nil, err
	}
	marshalledData = append(marshalledData, marshalledHeader...)

	// Marshalling content
	marshalledContent, err := k.Content.Marshal()
	if err != nil {
		return nil, err
	}
	marshalledData = append(marshalledData, marshalledContent...)

	return marshalledData, nil
}

// Describe prints a detailed description of the BCRYPT_ECC_PUBLIC_KEY structure.
//
// Parameters:
// - indent: An integer representing the indentation level for the printed output.
//
// Note:
// The function prints the Header and Data of the BCRYPT_ECC_PUBLIC_KEY structure.
// The output is formatted with the specified indentation level to improve readability.
func (k *BCRYPT_ECC_PUBLIC_KEY) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<\x1b[93mBCRYPT_ECC_PUBLIC_KEY\x1b[0m>\n", indentPrompt)
	k.Magic.Describe(indent + 1)
	k.Header.Describe(indent + 1)
	k.Content.Describe(indent + 1)
	fmt.Printf("%s└───\n", indentPrompt)
}

func isValidECCPublicMagic(m uint32) bool {
	switch m {
	case magic.BCRYPT_ECDH_PUBLIC_P256_MAGIC,
		magic.BCRYPT_ECDH_PUBLIC_P384_MAGIC,
		magic.BCRYPT_ECDH_PUBLIC_P521_MAGIC,
		magic.BCRYPT_ECDSA_PUBLIC_P256_MAGIC,
		magic.BCRYPT_ECDSA_PUBLIC_P384_MAGIC,
		magic.BCRYPT_ECDSA_PUBLIC_P521_MAGIC:
		return true
	default:
		return false
	}
}

// Fingerprint returns the fingerprint of the BCRYPT_ECC_PUBLIC_KEY structure.
//
// Parameters:
// - key: The BCRYPT_ECC_PUBLIC_KEY structure to get the fingerprint of.
//
// Returns:
// - A string representing the fingerprint of the BCRYPT_ECC_PUBLIC_KEY structure.
func (key *BCRYPT_ECC_PUBLIC_KEY) Fingerprint() string {
	return fmt.Sprintf("BCRYPT_ECC_PUBLIC_KEY:0x%x:0x%x", key.Content.X[:], key.Content.Y[:])
}
