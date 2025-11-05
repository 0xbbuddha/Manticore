package keys

import (
	"errors"
	"fmt"
	"strings"

	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/blob"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/headers"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/magic"
)

type BCRYPT_RSAPRIVATE_KEY struct {
	// Magic is the magic signature of the key.
	Magic magic.BCRYPT_KEY_BLOB

	// Header is the header of the key.
	Header headers.BCRYPT_RSAKEY_BLOB

	// Content is the content of the key.
	Content blob.BCRYPT_RSAPRIVATE_BLOB
}

// Unmarshal parses the provided byte slice into the BCRYPT_RSAPRIVATE_KEY structure.
//
// Parameters:
// - value: A byte slice containing the raw RSA private key to be parsed.
//
// Returns:
// - The number of bytes read from the byte slice.
// - An error if the parsing fails, otherwise nil.
//
// Note:
// The function expects the byte slice to follow the RSA private key format, starting with the BCRYPT_RSAKEY_BLOB header.
// It extracts the public exponent, modulus, prime1, and prime2 from the byte slice and stores them in the BCRYPT_RSAPRIVATE_KEY structure.
func (k *BCRYPT_RSAPRIVATE_KEY) Unmarshal(value []byte) (int, error) {
	if len(value) < 24 {
		return 0, errors.New("buffer too small for BCRYPT_RSAPRIVATE_KEY, header too short (at least 24 bytes are required)")
	}

	bytesRead := 0

	// Unmarshalling magic
	bytesRead, err := k.Magic.Unmarshal(value[:4])
	if err != nil {
		return 0, err
	}
	if k.Magic.Magic != magic.BCRYPT_RSAPRIVATE_MAGIC {
		return 0, fmt.Errorf("invalid RSA private key magic: 0x%08x", k.Magic.Magic)
	}

	// Unmarshalling header
	bytesRead, err = k.Header.Unmarshal(value[bytesRead:])
	if err != nil {
		return 0, err
	}
	bytesRead += int(k.Header.BitLength)

	// Unmarshalling content
	bytesRead, err = k.Content.Unmarshal(k.Header, value[bytesRead:])
	if err != nil {
		return 0, err
	}

	return bytesRead, nil
}

// Marshal returns the raw bytes of the BCRYPT_RSAPRIVATE_KEY structure.
//
// Returns:
// - A byte slice representing the raw bytes of the BCRYPT_RSAPRIVATE_KEY structure.
func (k *BCRYPT_RSAPRIVATE_KEY) Marshal() ([]byte, error) {
	marshalledData := []byte{}

	// Marshalling magic
	k.Magic.Magic = magic.BCRYPT_RSAPRIVATE_MAGIC
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

// Describe prints a detailed description of the BCRYPT_RSAPRIVATE_KEY structure.
//
// Parameters:
// - indent: An integer representing the indentation level for the printed output.
//
// Note:
// The function prints the Header and Data of the BCRYPT_RSAPRIVATE_KEY structure.
// The output is formatted with the specified indentation level to improve readability.
func (k *BCRYPT_RSAPRIVATE_KEY) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<\x1b[93mBCRYPT_RSAPRIVATE_KEY\x1b[0m>\n", indentPrompt)
	k.Magic.Describe(indent + 1)
	k.Header.Describe(indent + 1)
	k.Content.Describe(indent + 1)
	fmt.Printf("%s└───\n", indentPrompt)
}
