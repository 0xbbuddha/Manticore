package uuid_v4

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"github.com/TheManticoreProject/Manticore/crypto/uuid"
)

// UUIDv4 is a random-based UUID (version 4). It contains 122 bits of randomness
// with version and variant bits set per RFC 4122.
type UUIDv4 struct {
	uuid.UUID

	data [15]byte
}

// Generate fills the UUID with random bytes and sets version=4 and RFC 4122 variant.
func (u *UUIDv4) Generate() error {
	raw := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, raw); err != nil {
		return fmt.Errorf("uuid_v4: random read failed: %w", err)
	}

	// Set version (0100) and variant (10xx) in the raw layout
	raw[6] = (raw[6] & 0x0F) | (4 << 4)
	raw[8] = (raw[8] & 0x3F) | 0x80

	// Convert raw bytes into internal nibble-packed uuid.UUID.Data (15 bytes)
	copy(u.data[0:6], raw[0:6])
	u.data[6] = (raw[6]&0x0F)<<4 | (raw[7]&0xF0)>>4
	u.data[7] = (raw[7]&0x0F)<<4 | (raw[8] & 0x0F)
	copy(u.data[8:8+7], raw[9:9+7])

	u.UUID.Version = 4
	u.UUID.Variant = 0xA
	u.UUID.Data = u.data

	return nil
}

// Marshal converts the UUIDv4 structure to a 16-byte array. Call Generate() first.
func (u *UUIDv4) Marshal() ([]byte, error) {
	// Ensure version and variant are set correctly
	if u.UUID.Version == 0 {
		u.UUID.Version = 4
	}
	if u.UUID.Variant == 0 {
		u.UUID.Variant = 0xA
	}
	return u.UUID.Marshal()
}

// Unmarshal converts a 16-byte array into a UUIDv4 structure.
func (u *UUIDv4) Unmarshal(marshalledData []byte) (int, error) {
	if len(marshalledData) < 16 {
		return 0, fmt.Errorf("invalid UUID length: got %d bytes, want 16 bytes", len(marshalledData))
	}

	n, err := u.UUID.Unmarshal(marshalledData)
	if err != nil {
		return 0, err
	}

	if u.UUID.Version != 4 {
		return 0, fmt.Errorf("invalid UUID version: got %d, want 4", u.UUID.Version)
	}

	copy(u.data[:], u.UUID.Data[:])
	return n, nil
}

// FromString parses a UUID string in the format "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx".
func (u *UUIDv4) FromString(uuidStr string) error {
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

// String returns the canonical string form of the UUIDv4.
func (u *UUIDv4) String() string {
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
