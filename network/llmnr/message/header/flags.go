package header

import (
	"encoding/binary"
	"fmt"
	"strings"
)

type Flags uint16

// LLMNR Header Flags
const (
	FlagQR Flags = 1 << 15 // Query/Response flag
	FlagOP Flags = 1 << 14 // Operation code
	FlagC  Flags = 1 << 13 // Conflict flag
	FlagTC Flags = 1 << 12 // Truncation flag
	FlagT  Flags = 1 << 11 // Tentative flag
)

// IsQuery returns true if the flags are set for a query.
func (f Flags) IsQuery() bool {
	return f&FlagQR == 0
}

// IsResponse returns true if the flags are set for a response.
func (f Flags) IsResponse() bool {
	return f&FlagQR == FlagQR
}

// IsConflict returns true if the conflict flag is set.
func (f Flags) IsConflict() bool {
	return f&FlagC != 0
}

// IsTruncation returns true if the truncation flag is set.
func (f Flags) IsTruncation() bool {
	return f&FlagTC != 0
}

// IsTentative returns true if the tentative flag is set.
func (f Flags) IsTentative() bool {
	return f&FlagT != 0
}

// Marshal encodes the Flags into a 2-byte big-endian representation.
func (f *Flags) Marshal() ([]byte, error) {
	marshalledData := make([]byte, 2)
	binary.BigEndian.PutUint16(marshalledData, uint16(*f))
	return marshalledData, nil
}

// Unmarshal decodes a 2-byte big-endian representation into the Flags receiver.
// It returns an error if the input slice is not exactly 2 bytes.
func (f *Flags) Unmarshal(data []byte) (int, error) {
	if len(data) != 2 {
		return 0, fmt.Errorf("invalid length: got %d bytes, want 2 bytes", len(data))
	}

	bytesRead := 0
	*f = Flags(binary.BigEndian.Uint16(data[0:2]))
	bytesRead += 2

	return bytesRead, nil
}

// String returns a string representation of the flags.
func (f Flags) String() string {
	flags := []string{}
	if f.IsQuery() {
		flags = append(flags, "QR")
	}
	if f.IsResponse() {
		flags = append(flags, "OP")
	}
	if f.IsConflict() {
		flags = append(flags, "C")
	}
	if f.IsTruncation() {
		flags = append(flags, "TC")
	}
	if f.IsTentative() {
		flags = append(flags, "T")
	}
	return strings.Join(flags, "|")
}
