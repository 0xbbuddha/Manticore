package uuid_v3

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/TheManticoreProject/Manticore/crypto/uuid"
)

// UUIDv3 namespaces
// Source: https://www.rfc-editor.org/rfc/rfc4122#appendix-C
const (
	UUIDv3NamespaceDNS  = "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
	UUIDv3NamespaceURL  = "6ba7b811-9dad-11d1-80b4-00c04fd430c8"
	UUIDv3NamespaceOID  = "6ba7b812-9dad-11d1-80b4-00c04fd430c8"
	UUIDv3NamespaceX500 = "6ba7b814-9dad-11d1-80b4-00c04fd430c8"
)

// UUIDv3 is a name-based UUID (version 3). It is derived from
// MD5(namespaceUUID || name) with version=3 and RFC 4122 variant.
type UUIDv3 struct {
	uuid.UUID

	Namespace uuid.UUIDInterface

	Name string

	data [15]byte
}

// Marshal converts the UUIDv3 structure to a 16-byte array
//
// Returns:
//   - A byte slice containing the UUID's 16 bytes
//   - An error if the UUID is invalid or the conversion fails
func (u *UUIDv3) Marshal() ([]byte, error) {
	// Require namespace to be provided
	if u.Namespace == nil {
		return nil, fmt.Errorf("uuid_v3: missing namespace")
	}

	nsBytes, err := u.Namespace.Marshal()
	if err != nil {
		return nil, err
	}

	// Contents of UUIDv3 is MD5(namespace || name)
	md5Hash := md5.New()
	md5Hash.Write(nsBytes)
	md5Hash.Write([]byte(u.Name))
	hashBytes := md5Hash.Sum(nil)

	// Re-pack raw hash into uuid.UUID nibble layout (15-byte Data)
	hashBytesShifted := make([]byte, 0, 15)
	hashBytesShifted = append(hashBytesShifted, hashBytes[0:6]...)

	a := hashBytes[6]<<4 | (hashBytes[7] >> 4)
	hashBytesShifted = append(hashBytesShifted, a)

	b := hashBytes[7]<<4 | (hashBytes[8] & 0xF)
	hashBytesShifted = append(hashBytesShifted, b)

	hashBytesShifted = append(hashBytesShifted, hashBytes[9:]...)

	// Copy first 15 bytes
	copy(u.data[:], hashBytesShifted[0:15])

	// Version fixed to 3, variant set to RFC 4122 (10xx), preserving lower two high-nibble bits
	u.UUID.Version = 3
	u.UUID.Variant = 0x8 | ((hashBytes[8] >> 4) & 0x3)
	u.UUID.Data = u.data

	return u.UUID.Marshal()
}

// Unmarshal converts a 16-byte array into a UUIDv3 structure
//
// Returns:
//   - The number of bytes read
//   - An error if the UUID is invalid or the conversion fails
func (u *UUIDv3) Unmarshal(marshalledData []byte) (int, error) {
	if len(marshalledData) < 16 {
		return 0, fmt.Errorf("invalid UUID length: got %d bytes, want 16 bytes", len(marshalledData))
	}

	// First unmarshal into the generic UUID
	n, err := u.UUID.Unmarshal(marshalledData)
	if err != nil {
		return 0, err
	}

	// Check if this is a version 3 UUID
	if u.UUID.Version != 3 {
		return 0, fmt.Errorf("invalid UUID version: got %d, want 3", u.UUID.Version)
	}

	// Sync internal data nibble array from parsed uuid
	copy(u.data[:], u.UUID.Data[:])

	return n, nil
}

// FromString parses a UUID string in the format "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
// and returns a UUIDv3 structure.
//
// Parameters:
//   - uuidStr: A string containing the UUID in the format "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
//
// Returns:
//   - An error if the UUID is invalid or the conversion fails
func (u *UUIDv3) FromString(uuidStr string) error {

	uuidStr = strings.ReplaceAll(uuidStr, "-", "")

	if len(uuidStr) != 32 {
		return fmt.Errorf("invalid UUID length: got %d characters, want 32", len(uuidStr))
	}

	uuidStr = strings.ToLower(uuidStr)

	uuidBytes, err := hex.DecodeString(uuidStr)
	if err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}

	if len(uuidBytes) != 16 {
		return fmt.Errorf("invalid UUID length: got %d bytes, want 16", len(uuidBytes))
	}
	_, err = u.Unmarshal(uuidBytes)
	if err != nil {
		return fmt.Errorf("invalid UUID format: %v", err)
	}

	return nil
}

// String returns the string representation of the UUIDv3 structure
//
// Returns:
//   - The string representation of the UUIDv3 structure
func (u *UUIDv3) String() string {
	// Use the UUID's Marshal method to get the 16-byte array
	marshalledData, err := u.Marshal()
	if err != nil {
		return fmt.Sprintf("invalid UUID: %v", err)
	}

	return fmt.Sprintf(
		"%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(marshalledData[0:4]),
		binary.BigEndian.Uint16(marshalledData[4:6]),
		binary.BigEndian.Uint16(marshalledData[6:8]),
		binary.BigEndian.Uint16(marshalledData[8:10]),
		marshalledData[10:16],
	)
}
