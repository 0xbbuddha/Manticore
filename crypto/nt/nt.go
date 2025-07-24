package nt

import (
	"encoding/hex"
	"strings"

	"github.com/TheManticoreProject/Manticore/crypto/md4"
	"github.com/TheManticoreProject/Manticore/utils/encoding/utf16"
)

// NTHash computes the NT hash of a password string
// The NT hash is MD4(UTF16-LE(password))
func NTHash(password string) [16]byte {
	// Convert to UTF16 little endian bytes
	utf16lePassword := utf16.EncodeUTF16LE(password)

	// Calculate MD4 hash
	hash := md4.New()
	hash.Write(utf16lePassword)
	result := hash.Sum()

	return result
}

// NTHash computes the NT hash of a password string
// The NT hash is MD4(UTF16-LE(password))
func NTHashHex(password string) string {
	ntHash := NTHash(password)
	return strings.ToLower(hex.EncodeToString(ntHash[:]))
}

// NTOWFv1, this is the same as NTHash
// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/464551a8-9fc4-428e-b3d3-bc5bfb2e73a5
func NTOWFv1(Passwd, User, UserDom string) [16]byte {
	return NTHash(Passwd)
}
