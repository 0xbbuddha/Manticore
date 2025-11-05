package blob

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
	Header BCRYPT_RSAKEY_BLOB

	// PublicExponent is the public exponent of the RSA key.
	PublicExponent []byte // Big-endian.

	// Modulus is the modulus of the RSA key.
	Modulus []byte // Big-endian.
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
func (b *BCRYPT_RSAPUBLIC_BLOB) Unmarshal(value []byte) (int, error) {
	bytesRead, err := b.Header.Unmarshal(value)
	if err != nil {
		return 0, err
	}

	b.PublicExponent = value[bytesRead : int(bytesRead)+int(b.Header.CbPublicExp)]
	bytesRead += int(b.Header.CbPublicExp)

	b.Modulus = value[bytesRead : bytesRead+int(b.Header.CbModulus)]
	bytesRead += int(b.Header.CbModulus)

	return bytesRead, nil
}

// Marshal returns the raw bytes of the BCRYPT_RSAPUBLIC_BLOB structure.
//
// Returns:
// - A byte slice representing the raw bytes of the BCRYPT_RSAPUBLIC_BLOB structure.
func (b *BCRYPT_RSAPUBLIC_BLOB) Marshal() ([]byte, error) {
	marshalledData := []byte{}

	headerBytes, err := b.Header.Marshal()
	if err != nil {
		return nil, err
	}
	marshalledData = append(marshalledData, headerBytes...)

	marshalledData = append(marshalledData, b.PublicExponent...)

	marshalledData = append(marshalledData, b.Modulus...)

	return marshalledData, nil
}
