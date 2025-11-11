package keys

import (
	"errors"
	"fmt"
	"strings"

	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/blob"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/headers"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/magic"
)

type BCRYPT_RSA_PUBLIC_KEY struct {
	// Magic is the magic signature of the key.
	Magic magic.BCRYPT_KEY_BLOB

	// Header is the header of the key.
	Header headers.BCRYPT_RSA_KEY_BLOB

	// Content is the content of the key.
	Content blob.BCRYPT_RSA_PUBLIC_BLOB
}

// Unmarshal parses the provided byte slice into the BCRYPT_RSA_PUBLIC_KEY structure.
//
// Parameters:
// - value: A byte slice containing the raw RSA public key to be parsed.
//
// Returns:
// - The number of bytes read from the byte slice.
// - An error if the parsing fails, otherwise nil.
//
// Note:
// The function expects the byte slice to follow the RSA public key format, starting with the BCRYPT_RSA_KEY_BLOB header.
// It extracts the public exponent and modulus from the byte slice and stores them in the BCRYPT_RSA_PUBLIC_KEY structure.
func (k *BCRYPT_RSA_PUBLIC_KEY) Unmarshal(value []byte) (int, error) {
	if len(value) < 24 {
		return 0, errors.New("buffer too small for BCRYPT_RSA_PUBLIC_KEY, header too short (at least 24 bytes are required for magic and header)")
	}

	bytesRead := 0

	// Unmarshalling magic
	bytesReadMagic, err := k.Magic.Unmarshal(value[bytesRead:])
	if err != nil {
		return 0, fmt.Errorf("failed to unmarshal RSA public key magic: %w", err)
	}
	if k.Magic.Magic != magic.BCRYPT_RSAPUBLIC_MAGIC {
		return 0, fmt.Errorf("failed to unmarshal RSA public key magic: invalid magic: 0x%08x", k.Magic.Magic)
	}
	bytesRead += bytesReadMagic

	// Unmarshalling header
	bytesReadHeader, err := k.Header.Unmarshal(value[bytesRead:])
	if err != nil {
		return 0, fmt.Errorf("failed to unmarshal RSA public key header: %w", err)
	}
	bytesRead += bytesReadHeader
	k.Header.Describe(0)

	// Unmarshalling content
	bytesReadContent, err := k.Content.Unmarshal(k.Header, value[bytesRead:])
	if err != nil {
		return 0, fmt.Errorf("failed to unmarshal RSA public key content: %w", err)
	}
	bytesRead += bytesReadContent

	return bytesRead, nil
}

// Marshal returns the raw bytes of the BCRYPT_RSA_PUBLIC_KEY structure.
//
// Returns:
// - A byte slice representing the raw bytes of the BCRYPT_RSA_PUBLIC_KEY structure.
func (k *BCRYPT_RSA_PUBLIC_KEY) Marshal() ([]byte, error) {
	marshalledData := []byte{}

	// Marshalling magic
	k.Magic.Magic = magic.BCRYPT_RSAPUBLIC_MAGIC
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

// Describe prints a detailed description of the BCRYPT_RSA_PUBLIC_KEY structure.
//
// Parameters:
// - indent: An integer representing the indentation level for the printed output.
//
// Note:
// The function prints the Header and Data of the BCRYPT_RSA_PUBLIC_KEY structure.
// The output is formatted with the specified indentation level to improve readability.
func (k *BCRYPT_RSA_PUBLIC_KEY) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<\x1b[93mBCRYPT_RSA_PUBLIC_KEY\x1b[0m>\n", indentPrompt)
	k.Magic.Describe(indent + 1)
	k.Header.Describe(indent + 1)
	k.Content.Describe(indent + 1)
	fmt.Printf("%s └───\n", indentPrompt)
}

// Equal checks if two BCRYPT_RSA_PUBLIC_KEY structures are equal.
//
// Parameters:
// - other: The BCRYPT_RSA_PUBLIC_KEY structure to compare to.
//
// Returns:
// - True if the two BCRYPT_RSA_PUBLIC_KEY structures are equal, false otherwise.
func (k *BCRYPT_RSA_PUBLIC_KEY) Equal(other *BCRYPT_RSA_PUBLIC_KEY) bool {
	return k.Magic.Equal(&other.Magic) && k.Header.Equal(&other.Header) && k.Content.Equal(&other.Content)
}
