package blob

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/magic"
)

// BCRYPT_RSAKEY_BLOB structure is used as a header for an RSA public key or private key BLOB in memory.
//
// See:
// https://docs.microsoft.com/en-us/archive/msdn-magazine/2007/july/applying-cryptography-using-the-cng-api-in-windows-vista
// https://docs.microsoft.com/en-us/archive/msdn-magazine/2007/july/images/cc163389.fig11.gif
// https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
type BCRYPT_RSAKEY_BLOB struct {
	// Magic identifies the blob kind (public/private/full).
	Magic uint32

	// BitLength is the size, in bits, of the RSA key.
	BitLength uint32

	// CbPublicExp is the size, in bytes, of the public exponent.
	CbPublicExp uint32

	// CbModulus is the size, in bytes, of the modulus.
	CbModulus uint32

	// CbPrime1 is the size, in bytes, of the first prime (private only).
	CbPrime1 uint32

	// CbPrime2 is the size, in bytes, of the second prime (private only).
	CbPrime2 uint32
}

// Unmarshal parses the provided byte slice into the BCRYPT_RSAKEY_BLOB structure.
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
// the corresponding values from the body of the byte slice. The parsed values are stored in the BCRYPT_RSAKEY_BLOB structure.
//
// The function performs the following steps:
// 1. Sets the RawBytes and RawBytesSize fields to the provided byte slice and its length, respectively.
// 2. Checks if the blob type is "RSA1". If not, it returns an error.
// 3. Extracts the key size, exponent size, modulus size, prime1 size, and prime2 size from the header.
// 4. Parses the exponent, modulus, prime1, and prime2 values from the body of the byte slice based on the extracted sizes.
// 5. Stores the parsed values in the corresponding fields of the BCRYPT_RSAKEY_BLOB structure.
func (rk *BCRYPT_RSAKEY_BLOB) Unmarshal(value []byte) (int, error) {
	if len(value) < 24 {
		return 0, errors.New("buffer too small for BCRYPT_RSAKEY_BLOB, header too short (at least 24 bytes are required)")
	}

	rk.Magic = binary.BigEndian.Uint32(value[:4])
	if rk.Magic != magic.BCRYPT_RSAPUBLIC_MAGIC && rk.Magic != magic.BCRYPT_RSAPRIVATE_MAGIC && rk.Magic != magic.BCRYPT_RSAFULLPRIVATE_MAGIC {
		return 0, fmt.Errorf("invalid RSA key magic: 0x%08x", rk.Magic)
	}

	rk.BitLength = binary.BigEndian.Uint32(value[4:8])

	rk.CbPublicExp = binary.BigEndian.Uint32(value[8:12])

	rk.CbModulus = binary.BigEndian.Uint32(value[12:16])

	rk.CbPrime1 = binary.BigEndian.Uint32(value[16:20])
	if rk.CbPrime1 == 0 && (rk.Magic == magic.BCRYPT_RSAPRIVATE_MAGIC || rk.Magic == magic.BCRYPT_RSAFULLPRIVATE_MAGIC) {
		return 0, fmt.Errorf("prime1 size is 0, private key needs to have prime1")
	}
	if rk.CbPrime1 != 0 && rk.Magic == magic.BCRYPT_RSAPUBLIC_MAGIC {
		return 0, fmt.Errorf("prime1 size is not 0, public key cannot have prime1")
	}

	rk.CbPrime2 = binary.BigEndian.Uint32(value[20:24])
	if rk.CbPrime2 == 0 && (rk.Magic == magic.BCRYPT_RSAPRIVATE_MAGIC || rk.Magic == magic.BCRYPT_RSAFULLPRIVATE_MAGIC) {
		return 0, fmt.Errorf("prime2 size is 0, private key needs to have prime2")
	}
	if rk.CbPrime2 != 0 && rk.Magic == magic.BCRYPT_RSAPUBLIC_MAGIC {
		return 0, fmt.Errorf("prime2 size is not 0, public key cannot have prime2")
	}

	return 24, nil
}

// Marshal returns the raw bytes of the BCRYPT_RSAKEY_BLOB structure.
//
// Returns:
// - A byte slice representing the raw bytes of the BCRYPT_RSAKEY_BLOB structure.
func (rk *BCRYPT_RSAKEY_BLOB) Marshal() ([]byte, error) {
	buf := make([]byte, 24)

	binary.BigEndian.PutUint32(buf[:4], rk.Magic)

	binary.BigEndian.PutUint32(buf[4:8], rk.BitLength)

	binary.BigEndian.PutUint32(buf[8:12], rk.CbPublicExp)

	binary.BigEndian.PutUint32(buf[12:16], rk.CbModulus)

	binary.BigEndian.PutUint32(buf[16:20], rk.CbPrime1)

	binary.BigEndian.PutUint32(buf[20:24], rk.CbPrime2)

	return buf, nil
}

// Describe prints a detailed description of the BCRYPT_RSAKEY_BLOB instance.
//
// Parameters:
// - indent: An integer representing the indentation level for the printed output.
//
// Note:
// This function prints the Exponent, Modulus, Prime1, and Prime2 values of the BCRYPT_RSAKEY_BLOB instance.
// The output is formatted with the specified indentation level to improve readability.
// If Prime1 or Prime2 is not set, the function prints "None" for the respective value.
func (rk *BCRYPT_RSAKEY_BLOB) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<\x1b[93mBCRYPT_RSAKEY_BLOB (header)\x1b[0m>\n", indentPrompt)
	fmt.Printf("%s │ \x1b[93mExponent (E)\x1b[0m: %d\n", indentPrompt, rk.CbPublicExp)
	fmt.Printf("%s │ \x1b[93mModulus (N) \x1b[0m: 0x%x\n", indentPrompt, rk.CbModulus)
	fmt.Printf("%s │ \x1b[93mPrime1 (P)  \x1b[0m: 0x%x\n", indentPrompt, rk.CbPrime1)
	fmt.Printf("%s │ \x1b[93mPrime2 (Q)  \x1b[0m: 0x%x\n", indentPrompt, rk.CbPrime2)
	fmt.Printf("%s └───\n", indentPrompt)
}

// Equal checks if two BCRYPT_RSAKEY_BLOB structures are equal.
//
// Parameters:
// - other: The BCRYPT_RSAKEY_BLOB structure to compare to.
//
// Returns:
// - True if the two BCRYPT_RSAKEY_BLOB structures are equal, false otherwise.
func (rk *BCRYPT_RSAKEY_BLOB) Equal(other *BCRYPT_RSAKEY_BLOB) bool {
	return rk.Magic == other.Magic && rk.BitLength == other.BitLength && rk.CbPublicExp == other.CbPublicExp && rk.CbModulus == other.CbModulus && rk.CbPrime1 == other.CbPrime1 && rk.CbPrime2 == other.CbPrime2
}

// String returns a string representation of the BCRYPT_RSAKEY_BLOB structure.
//
// Returns:
// - A string representing the BCRYPT_RSAKEY_BLOB structure.
func (rk *BCRYPT_RSAKEY_BLOB) String() string {
	return fmt.Sprintf("BCRYPT_RSAKEY_BLOB(Magic: 0x%08x, BitLength: %d, CbPublicExp: %d, CbModulus: %d, CbPrime1: %d, CbPrime2: %d)", rk.Magic, rk.BitLength, rk.CbPublicExp, rk.CbModulus, rk.CbPrime1, rk.CbPrime2)
}
