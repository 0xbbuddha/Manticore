package blob

import (
	"errors"

	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/headers"
)

// BCRYPT_RSAPRIVATE_BLOB represents the structure used as a header for an RSA private key BLOB in memory.
//
// The layout of a BCRYPT_RSAPRIVATE_BLOB in memory is as follows:
//
//	BCRYPT_RSAPRIVATE_BLOB
//	PublicExponent[cbPublicExp] // Big-endian
//	Modulus[cbModulus]         // Big-endian
//	Prime1[cbPrime1] // Big-endian
//	Prime2[cbPrime2] // Big-endian
//
// The fields following this structure (PublicExponent, Modulus, Prime1, and Prime2) are stored in big-endian format.
//
// See:
// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
type BCRYPT_RSAPRIVATE_BLOB struct {
	// PublicExponent is the public exponent of the RSA key.
	PublicExponent []byte // Big-endian.

	// Modulus is the modulus of the RSA key.
	Modulus []byte // Big-endian.

	// Prime1 is the first prime of the RSA key.
	Prime1 []byte // Big-endian.

	// Prime2 is the second prime of the RSA key.
	Prime2 []byte // Big-endian.
}

// Unmarshal parses the provided byte slice into the BCRYPT_RSAPRIVATE_BLOB structure.
//
// Parameters:
// - value: A byte slice containing the raw RSA private key BLOB to be parsed.
//
// Returns:
// - The number of bytes read from the byte slice.
// - An error if the parsing fails, otherwise nil.
//
// Note:
// The function expects the byte slice to follow the RSA private key BLOB format, starting with the BCRYPT_RSAKEY_BLOB header.
// It extracts the public exponent, modulus, prime1, and prime2 from the byte slice and stores them in the BCRYPT_RSAPRIVATE_BLOB structure.
func (b *BCRYPT_RSAPRIVATE_BLOB) Unmarshal(keyHeader headers.BCRYPT_RSAKEY_BLOB, value []byte) (int, error) {
	bytesRead := 0

	if int(keyHeader.CbPublicExp) > len(value)-bytesRead {
		return 0, errors.New("buffer too small for BCRYPT_RSAPRIVATE_BLOB, not enough bytes for unmarshalling public exponent")
	}
	b.PublicExponent = value[bytesRead : bytesRead+int(keyHeader.CbPublicExp)]
	bytesRead += int(keyHeader.CbPublicExp)

	if int(keyHeader.CbModulus) > len(value)-bytesRead {
		return 0, errors.New("buffer too small for BCRYPT_RSAPRIVATE_BLOB, not enough bytes for unmarshalling modulus")
	}
	b.Modulus = value[bytesRead : bytesRead+int(keyHeader.CbModulus)]
	bytesRead += int(keyHeader.CbModulus)

	if int(keyHeader.CbPrime1) > len(value)-bytesRead {
		return 0, errors.New("buffer too small for BCRYPT_RSAPRIVATE_BLOB, not enough bytes for unmarshalling prime1")
	}
	b.Prime1 = value[bytesRead : bytesRead+int(keyHeader.CbPrime1)]
	bytesRead += int(keyHeader.CbPrime1)

	if int(keyHeader.CbPrime2) > len(value)-bytesRead {
		return 0, errors.New("buffer too small for BCRYPT_RSAPRIVATE_BLOB, not enough bytes for unmarshalling prime2")
	}
	b.Prime2 = value[bytesRead : bytesRead+int(keyHeader.CbPrime2)]
	bytesRead += int(keyHeader.CbPrime2)

	return bytesRead, nil
}

// Marshal returns the raw bytes of the BCRYPT_RSAPRIVATE_BLOB structure.
//
// Returns:
// - A byte slice representing the raw bytes of the BCRYPT_RSAPRIVATE_BLOB structure.
func (b *BCRYPT_RSAPRIVATE_BLOB) Marshal() ([]byte, error) {
	marshalledData := []byte{}

	marshalledData = append(marshalledData, b.PublicExponent...)

	marshalledData = append(marshalledData, b.Modulus...)

	marshalledData = append(marshalledData, b.Prime1...)

	marshalledData = append(marshalledData, b.Prime2...)

	return marshalledData, nil
}
