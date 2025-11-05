package blob

import (
	"errors"

	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/headers"
)

// BCRYPT_RSAPUBLIC_BLOB represents the structure used as a header for an RSA public key BLOB in memory.
//
// The layout of a BCRYPT_RSAPUBLIC_BLOB in memory is as follows:
//
//	BCRYPT_RSAPUBLIC_BLOB
//	PublicExponent[cbPublicExp] // Big-endian
//	Modulus[cbModulus]         // Big-endian
//
// The fields following this structure (PublicExponent and Modulus) are stored in big-endian format.
//
// See:
// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
type BCRYPT_RSAPUBLIC_BLOB struct {
	// PublicExponent is the public exponent of the RSA key.
	// Stored in big-endian format.
	PublicExponent []byte

	// Modulus is the modulus of the RSA key.
	// Stored in big-endian format.
	Modulus []byte
}

// Unmarshal parses the provided byte slice into the BCRYPT_RSAPUBLIC_BLOB structure.
//
// Parameters:
// - value: A byte slice containing the raw RSA public key BLOB to be parsed.
//
// Returns:
// - The number of bytes read from the byte slice.
// - An error if the parsing fails, otherwise nil.
//
// Note:
// The function expects the byte slice to follow the RSA public key BLOB format, starting with the BCRYPT_RSAKEY_BLOB header.
// It extracts the public exponent and modulus from the byte slice and stores them in the BCRYPT_RSAPUBLIC_BLOB structure.
func (b *BCRYPT_RSAPUBLIC_BLOB) Unmarshal(keyHeader headers.BCRYPT_RSAKEY_BLOB, value []byte) (int, error) {
	bytesRead := 0

	if int(keyHeader.CbPublicExp) > len(value)-bytesRead {
		return 0, errors.New("buffer too small for BCRYPT_RSAPUBLIC_BLOB, not enough bytes for unmarshalling public exponent")
	}
	b.PublicExponent = value[bytesRead : bytesRead+int(keyHeader.CbPublicExp)]
	bytesRead += int(keyHeader.CbPublicExp)

	if int(keyHeader.CbModulus) > len(value)-bytesRead {
		return 0, errors.New("buffer too small for BCRYPT_RSAPUBLIC_BLOB, not enough bytes for unmarshalling modulus")
	}
	b.Modulus = value[bytesRead : bytesRead+int(keyHeader.CbModulus)]
	bytesRead += int(keyHeader.CbModulus)

	return bytesRead, nil
}

// Marshal returns the raw bytes of the BCRYPT_RSAPUBLIC_BLOB structure.
//
// Returns:
// - A byte slice representing the raw bytes of the BCRYPT_RSAPUBLIC_BLOB structure.
func (b *BCRYPT_RSAPUBLIC_BLOB) Marshal() ([]byte, error) {
	marshalledData := []byte{}

	marshalledData = append(marshalledData, b.PublicExponent...)

	marshalledData = append(marshalledData, b.Modulus...)

	return marshalledData, nil
}
