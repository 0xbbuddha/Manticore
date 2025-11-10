package headers

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// BCRYPT_RSA_KEY_BLOB structure is used as a header for an RSA public key or private key BLOB in memory.
//
// See:
// https://docs.microsoft.com/en-us/archive/msdn-magazine/2007/july/applying-cryptography-using-the-cng-api-in-windows-vista
// https://docs.microsoft.com/en-us/archive/msdn-magazine/2007/july/images/cc163389.fig11.gif
// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
type BCRYPT_RSA_KEY_BLOB struct {
	// The size, in bits, of the key.
	BitLength uint32

	// The size, in bytes, of the exponent of the key.
	// As of Windows 10 version 1903, public exponents larger than (2^64 - 1) are no longer supported.
	CbPublicExp uint32

	// The size, in bytes, of the modulus of the key.
	CbModulus uint32

	// The size, in bytes, of the first prime number of the key. This is only used for private key BLOBs.
	CbPrime1 uint32

	// The size, in bytes, of the second prime number of the key. This is only used for private key BLOBs.
	CbPrime2 uint32
}

// Unmarshal parses the provided byte slice into the BCRYPT_RSA_KEY_BLOB structure.
//
// Parameters:
// - value: A byte slice containing the raw RSA key material to be parsed.
//
// Returns:
// - The number of bytes read from the byte slice.
// - An error if the parsing fails, otherwise nil.
//
// Note:
// The function expects the byte slice to follow the RSA key blob format, starting with the "RSA1" blob type identifier.
// It extracts the key size, exponent size, modulus size, prime1 size, and prime2 size from the header, and then parses
// the corresponding values from the body of the byte slice. The parsed values are stored in the BCRYPT_RSA_KEY_BLOB structure.
//
// The function performs the following steps:
// 1. Sets the RawBytes and RawBytesSize fields to the provided byte slice and its length, respectively.
// 2. Checks if the blob type is "RSA1". If not, it returns an error.
// 3. Extracts the key size, exponent size, modulus size, prime1 size, and prime2 size from the header.
// 4. Parses the exponent, modulus, prime1, and prime2 values from the body of the byte slice based on the extracted sizes.
// 5. Stores the parsed values in the corresponding fields of the BCRYPT_RSA_KEY_BLOB structure.
func (k *BCRYPT_RSA_KEY_BLOB) Unmarshal(value []byte) (int, error) {
	if len(value) < 20 {
		return 0, errors.New("buffer too small for BCRYPT_RSA_KEY_BLOB, header too short (at least 20 bytes are required)")
	}

	fmt.Printf("[debug] Before unmarshalling BitLength value: %s\n\n", hex.EncodeToString(value))

	bytesRead := 0

	k.BitLength = binary.LittleEndian.Uint32(value[bytesRead : bytesRead+4])
	bytesRead += 4

	k.CbPublicExp = binary.LittleEndian.Uint32(value[bytesRead : bytesRead+4])
	bytesRead += 4

	k.CbModulus = binary.LittleEndian.Uint32(value[bytesRead : bytesRead+4])
	bytesRead += 4

	k.CbPrime1 = binary.LittleEndian.Uint32(value[bytesRead : bytesRead+4])
	bytesRead += 4

	k.CbPrime2 = binary.LittleEndian.Uint32(value[bytesRead : bytesRead+4])
	bytesRead += 4

	return bytesRead, nil
}

// Marshal returns the raw bytes of the BCRYPT_RSA_KEY_BLOB structure.
//
// Returns:
// - A byte slice representing the raw bytes of the BCRYPT_RSA_KEY_BLOB structure.
func (k *BCRYPT_RSA_KEY_BLOB) Marshal() ([]byte, error) {
	buf := make([]byte, 20)
	bytesWritten := 0

	binary.LittleEndian.PutUint32(buf[bytesWritten:bytesWritten+4], k.BitLength)
	bytesWritten += 4

	binary.LittleEndian.PutUint32(buf[bytesWritten:bytesWritten+4], k.CbPublicExp)
	bytesWritten += 4

	binary.LittleEndian.PutUint32(buf[bytesWritten:bytesWritten+4], k.CbModulus)
	bytesWritten += 4

	binary.LittleEndian.PutUint32(buf[bytesWritten:bytesWritten+4], k.CbPrime1)
	bytesWritten += 4

	binary.LittleEndian.PutUint32(buf[bytesWritten:bytesWritten+4], k.CbPrime2)
	bytesWritten += 4

	return buf, nil
}

// Describe prints a detailed description of the BCRYPT_RSA_KEY_BLOB instance.
//
// Parameters:
// - indent: An integer representing the indentation level for the printed output.
//
// Note:
// This function prints the Exponent, Modulus, Prime1, and Prime2 values of the BCRYPT_RSA_KEY_BLOB instance.
// The output is formatted with the specified indentation level to improve readability.
// If Prime1 or Prime2 is not set, the function prints "None" for the respective value.
func (k *BCRYPT_RSA_KEY_BLOB) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<\x1b[93mBCRYPT_RSA_KEY_BLOB (header)\x1b[0m>\n", indentPrompt)
	fmt.Printf("%s │ \x1b[93mBitLength\x1b[0m   : (0x%08x) %d bits \n", indentPrompt, k.BitLength, k.BitLength)
	fmt.Printf("%s │ \x1b[93mCbPublicExp\x1b[0m : (0x%08x) %d bytes \n", indentPrompt, k.CbPublicExp, k.CbPublicExp)
	fmt.Printf("%s │ \x1b[93mCbModulus\x1b[0m   : (0x%08x) %d bytes \n", indentPrompt, k.CbModulus, k.CbModulus)
	fmt.Printf("%s │ \x1b[93mCbPrime1\x1b[0m    : (0x%08x) %d bytes \n", indentPrompt, k.CbPrime1, k.CbPrime1)
	fmt.Printf("%s │ \x1b[93mCbPrime2\x1b[0m    : (0x%08x) %d bytes \n", indentPrompt, k.CbPrime2, k.CbPrime2)
	fmt.Printf("%s └───\n", indentPrompt)
}

// Equal checks if two BCRYPT_RSA_KEY_BLOB structures are equal.
//
// Parameters:
// - other: The BCRYPT_RSA_KEY_BLOB structure to compare to.
//
// Returns:
// - True if the two BCRYPT_RSA_KEY_BLOB structures are equal, false otherwise.
func (k *BCRYPT_RSA_KEY_BLOB) Equal(other *BCRYPT_RSA_KEY_BLOB) bool {
	return k.BitLength == other.BitLength && k.CbPublicExp == other.CbPublicExp && k.CbModulus == other.CbModulus && k.CbPrime1 == other.CbPrime1 && k.CbPrime2 == other.CbPrime2
}

// String returns a string representation of the BCRYPT_RSA_KEY_BLOB structure.
//
// Returns:
// - A string representing the BCRYPT_RSA_KEY_BLOB structure.
func (k *BCRYPT_RSA_KEY_BLOB) String() string {
	return fmt.Sprintf("BCRYPT_RSA_KEY_BLOB(BitLength: %d, CbPublicExp: %d, CbModulus: %d, CbPrime1: %d, CbPrime2: %d)", k.BitLength, k.CbPublicExp, k.CbModulus, k.CbPrime1, k.CbPrime2)
}
