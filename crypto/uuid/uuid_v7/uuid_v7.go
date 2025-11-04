package uuid_v7

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/TheManticoreProject/Manticore/crypto/uuid"
)

// UUIDv7 is a Unix-time and randomness based UUID (version 7) per RFC 4122bis.
// It embeds a 48-bit Unix millisecond timestamp and 74 bits of randomness
// with version and variant bits set accordingly.
type UUIDv7 struct {
	uuid.UUID

	data [15]byte
}

// Generate creates a UUIDv7 using the current Unix time in milliseconds and random bits.
func (u *UUIDv7) Generate() error {
	// 48-bit unix millis
	ms := uint64(time.Now().UnixMilli())
	raw := make([]byte, 16)
	raw[0] = byte(ms >> 40)
	raw[1] = byte(ms >> 32)
	raw[2] = byte(ms >> 24)
	raw[3] = byte(ms >> 16)
	raw[4] = byte(ms >> 8)
	raw[5] = byte(ms)

	// 10 bytes randomness
	r := make([]byte, 10)
	if _, err := io.ReadFull(rand.Reader, r); err != nil {
		return fmt.Errorf("uuid_v7: random read failed: %w", err)
	}

	// rand_a (12 bits): low nibble of byte6 and full byte7
	raw[6] = 0x70 | (r[0] & 0x0F) // version 7 in high nibble
	raw[7] = r[1]

	// variant (10xx) and remaining 62-bit randomness
	raw[8] = (r[2] & 0x3F) | 0x80
	copy(raw[9:], r[3:])

	// Map raw into internal nibble-packed uuid.UUID.Data
	copy(u.data[0:6], raw[0:6])
	u.data[6] = (raw[6]&0x0F)<<4 | (raw[7]&0xF0)>>4
	u.data[7] = (raw[7]&0x0F)<<4 | (raw[8] & 0x0F)
	copy(u.data[8:8+7], raw[9:9+7])

	u.UUID.Version = 7
	u.UUID.Variant = 0xA
	u.UUID.Data = u.data
	return nil
}

// Marshal converts the UUIDv7 structure to a 16-byte array.
func (u *UUIDv7) Marshal() ([]byte, error) {
	if u.UUID.Version == 0 {
		u.UUID.Version = 7
	}
	if u.UUID.Variant == 0 {
		u.UUID.Variant = 0xA
	}
	return u.UUID.Marshal()
}

// Unmarshal converts a 16-byte array into a UUIDv7 structure.
func (u *UUIDv7) Unmarshal(marshalledData []byte) (int, error) {
	if len(marshalledData) < 16 {
		return 0, fmt.Errorf("invalid UUID length: got %d bytes, want 16 bytes", len(marshalledData))
	}

	n, err := u.UUID.Unmarshal(marshalledData)
	if err != nil {
		return 0, err
	}
	if u.UUID.Version != 7 {
		return 0, fmt.Errorf("invalid UUID version: got %d, want 7", u.UUID.Version)
	}
	copy(u.data[:], u.UUID.Data[:])
	return n, nil
}

// FromString parses a UUID string and validates that it is version 7.
func (u *UUIDv7) FromString(uuidStr string) error {
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

// GetTime returns the Unix time represented by the UUIDv7 timestamp (milliseconds precision).
func (u *UUIDv7) GetTime() time.Time {
	marshalledData, err := u.Marshal()
	if err != nil {
		return time.Unix(0, 0)
	}
	ms := (uint64(marshalledData[0]) << 40) |
		(uint64(marshalledData[1]) << 32) |
		(uint64(marshalledData[2]) << 24) |
		(uint64(marshalledData[3]) << 16) |
		(uint64(marshalledData[4]) << 8) |
		uint64(marshalledData[5])
	return time.Unix(0, int64(ms)*int64(time.Millisecond))
}

// String returns the canonical string form of the UUIDv7.
func (u *UUIDv7) String() string {
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
