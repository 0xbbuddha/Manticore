package crypto

import (
	"github.com/TheManticoreProject/Manticore/windows/keycredential/key/strength"
	"github.com/TheManticoreProject/Manticore/windows/keycredential/key/usage"

	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
)

// RSAKeyMaterial represents the RSA key material structure.
//
// See:
// https://docs.microsoft.com/en-us/archive/msdn-magazine/2007/july/applying-cryptography-using-the-cng-api-in-windows-vista
// https://docs.microsoft.com/en-us/archive/msdn-magazine/2007/july/images/cc163389.fig11.gif
// https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_rsakey_blob
type RSAKeyMaterial struct {
	KeyUsage    usage.KeyUsage
	KeyStrength strength.KeyStrength

	Exponent uint32
	Modulus  []byte
	Prime1   []byte
	Prime2   []byte
	KeySize  uint32

	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

// Unmarshal parses the provided byte slice into the RSAKeyMaterial structure.
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
// the corresponding values from the body of the byte slice. The parsed values are stored in the RSAKeyMaterial structure.
//
// The function performs the following steps:
// 1. Sets the RawBytes and RawBytesSize fields to the provided byte slice and its length, respectively.
// 2. Checks if the blob type is "RSA1". If not, it returns an error.
// 3. Extracts the key size, exponent size, modulus size, prime1 size, and prime2 size from the header.
// 4. Parses the exponent, modulus, prime1, and prime2 values from the body of the byte slice based on the extracted sizes.
// 5. Stores the parsed values in the corresponding fields of the RSAKeyMaterial structure.
func (rk *RSAKeyMaterial) Unmarshal(value []byte) (int, error) {
	rk.RawBytes = value
	rk.RawBytesSize = uint32(len(value))

	bytesRead := 0

	// Parsing header
	blobType := value[:4]
	if string(blobType) != "RSA1" {
		return bytesRead, fmt.Errorf("invalid blob type: %s", string(blobType))
	}
	bytesRead += 4

	rk.KeySize = binary.LittleEndian.Uint32(value[4:8])
	bytesRead += 4

	exponentSize := binary.LittleEndian.Uint32(value[8:12])
	bytesRead += 4

	modulusSize := binary.LittleEndian.Uint32(value[12:16])
	bytesRead += 4

	prime1Size := binary.LittleEndian.Uint32(value[16:20])
	bytesRead += 4

	prime2Size := binary.LittleEndian.Uint32(value[20:24])
	bytesRead += 4

	// Parsing data section

	// For some reason, the exponent is stored in big-endian format.
	rk.Exponent = 0
	for i := 0; i < int(exponentSize); i++ {
		rk.Exponent = (rk.Exponent << 8) | uint32(value[bytesRead+i])
	}
	bytesRead += int(exponentSize)

	rk.Modulus = value[bytesRead : bytesRead+int(modulusSize)]
	bytesRead += int(modulusSize)
	rk.Prime1 = value[bytesRead : bytesRead+int(prime1Size)]
	bytesRead += int(prime1Size)
	rk.Prime2 = value[bytesRead : bytesRead+int(prime2Size)]
	bytesRead += int(prime2Size)

	return bytesRead, nil
}

// Marshal returns the raw bytes of the RSAKeyMaterial structure.
//
// Returns:
// - A byte slice representing the raw bytes of the RSAKeyMaterial structure.
func (rk *RSAKeyMaterial) Marshal() ([]byte, error) {
	b_blobType := []byte("RSA1")
	b_keySize := make([]byte, 4)
	binary.LittleEndian.PutUint32(b_keySize, rk.KeySize)

	b_exponent := make([]byte, 4)
	binary.BigEndian.PutUint32(b_exponent, rk.Exponent)
	b_exponentSize := make([]byte, 4)
	binary.LittleEndian.PutUint32(b_exponentSize, uint32(len(b_exponent)))

	b_modulusSize := make([]byte, 4)
	binary.LittleEndian.PutUint32(b_modulusSize, uint32(len(rk.Modulus)))

	var b_prime1, b_prime1Size []byte
	if len(rk.Prime1) == 0 {
		b_prime1Size = make([]byte, 4)
		binary.LittleEndian.PutUint32(b_prime1Size, 0)
	} else {
		b_prime1 = rk.Prime1
		b_prime1Size = make([]byte, 4)
		binary.LittleEndian.PutUint32(b_prime1Size, uint32(len(b_prime1)))
	}

	var b_prime2, b_prime2Size []byte
	if len(rk.Prime2) == 0 {
		b_prime2Size = make([]byte, 4)
		binary.LittleEndian.PutUint32(b_prime2Size, 0)
	} else {
		b_prime2 = rk.Prime2
		b_prime2Size = make([]byte, 4)
		binary.LittleEndian.PutUint32(b_prime2Size, uint32(len(b_prime2)))
	}

	// Header
	data := append(b_blobType, b_keySize...)
	data = append(data, b_exponentSize...)
	data = append(data, b_modulusSize...)
	data = append(data, b_prime1Size...)
	data = append(data, b_prime2Size...)

	// Content
	data = append(data, b_exponent...)
	data = append(data, rk.Modulus...)
	if len(rk.Prime1) != 0 {
		data = append(data, b_prime1...)
	}
	if len(rk.Prime2) != 0 {
		data = append(data, b_prime2...)
	}

	return data, nil
}

// Describe prints a detailed description of the RSAKeyMaterial instance.
//
// Parameters:
// - indent: An integer representing the indentation level for the printed output.
//
// Note:
// This function prints the Exponent, Modulus, Prime1, and Prime2 values of the RSAKeyMaterial instance.
// The output is formatted with the specified indentation level to improve readability.
// If Prime1 or Prime2 is not set, the function prints "None" for the respective value.
func (rk *RSAKeyMaterial) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<\x1b[93mRSAKeyMaterial\x1b[0m>\n", indentPrompt)
	fmt.Printf("%s │ \x1b[93mExponent (E)\x1b[0m: %d\n", indentPrompt, rk.Exponent)
	fmt.Printf("%s │ \x1b[93mModulus (N)\x1b[0m: 0x%s\n", indentPrompt, hex.EncodeToString(rk.Modulus))

	if len(rk.Prime1) != 0 {
		fmt.Printf("%s │ \x1b[93mPrime1 (P)\x1b[0m: 0x%s\n", indentPrompt, hex.EncodeToString(rk.Prime1))
	} else {
		fmt.Printf("%s │ \x1b[93mPrime1 (P)\x1b[0m: None\n", indentPrompt)
	}

	if len(rk.Prime2) != 0 {
		fmt.Printf("%s │ \x1b[93mPrime2 (Q)\x1b[0m: 0x%s\n", indentPrompt, hex.EncodeToString(rk.Prime2))
	} else {
		fmt.Printf("%s │ \x1b[93mPrime2 (Q)\x1b[0m: None\n", indentPrompt)
	}

	fmt.Printf("%s └───\n", indentPrompt)
}

// String returns a string representation of the RSAKeyMaterial structure.
//
// Returns:
// - A string representing the RSAKeyMaterial structure.
func (rk *RSAKeyMaterial) String() string {
	return fmt.Sprintf("%05d:%s", rk.Exponent, hex.EncodeToString(rk.Modulus))
}

// ExportPEM exports the RSA key material to a PEM-encoded string.
//
// Returns:
// - A string containing the PEM-encoded RSA key material.
//
// Note:
// This function converts the RSA key material to the PKCS#1 RSAPrivateKey format and encodes it in PEM format.
// The PEM-encoded string can be used to store or transfer the RSA key material in a standardized format.
func ExportPrivateKeyToPEM(rk *RSAKeyMaterial) string {
	privateKey := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			N: new(big.Int).SetBytes(rk.Modulus),
			E: int(rk.Exponent),
		},
		Primes: []*big.Int{
			new(big.Int).SetBytes(rk.Prime1),
			new(big.Int).SetBytes(rk.Prime2),
		},
	}

	privateKey.Precompute()

	der := x509.MarshalPKCS1PrivateKey(privateKey)

	// Encode the DER bytes to PEM format
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	}

	return string(pem.EncodeToMemory(pemBlock))
}

// ExportPublicKeyToPEM exports the RSA key material to a PEM-encoded string.
//
// Returns:
// - A string containing the PEM-encoded RSA key material.
//
// Note:
// This function converts the RSA key material to the PKCS#1 RSAPublicKey format and encodes it in PEM format.
// The PEM-encoded string can be used to store or transfer the RSA key material in a standardized format.
func (rk *RSAKeyMaterial) ExportPublicKeyToPEM(path string) error {
	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(rk.Modulus),
		E: int(rk.Exponent),
	}

	der := x509.MarshalPKCS1PublicKey(publicKey)

	pemBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: der,
	}

	// Create the directory if it doesn't exist
	dir := filepath.Dir(path)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err := os.MkdirAll(dir, os.ModePerm)
		if err != nil {
			return err
		}
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	pem.Encode(file, pemBlock)

	return nil
}
