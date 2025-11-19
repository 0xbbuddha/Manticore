package class

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Class represents the class field in an LLMNR question.
//
// LLMNR reuses DNS classes, with an additional "QU" (Unicast-Preferred) bit
// in the most significant bit of the class field as defined by RFC 4795.
// When the QU bit is set, the responder should prefer sending a unicast response.
type Class uint16

// LLMNR Question Classes and Flags.
const (
	// Base classes (DNS-compatible)
	ClassIN   Class = 1   // Internet
	ClassCS   Class = 2   // CSNET (Obsolete)
	ClassCH   Class = 3   // CHAOS
	ClassHS   Class = 4   // Hesiod
	ClassNONE Class = 254 // Used in dynamic update messages
	ClassANY  Class = 255 // Any class

	// QU (Unicast-Preferred) flag for LLMNR questions (MSB of the class field)
	ClassUnicastPreferred Class = 1 << 15
)

// IsUnicastPreferred returns true if the QU (Unicast-Preferred) bit is set.
func (c Class) IsUnicastPreferred() bool {
	return c&ClassUnicastPreferred != 0
}

// BaseClass returns the class value with the QU bit cleared.
func (c Class) BaseClass() Class {
	return c &^ ClassUnicastPreferred
}

// Marshal encodes the Class into a 2-byte big-endian representation.
func (c *Class) Marshal() ([]byte, error) {
	marshalledData := make([]byte, 2)
	binary.BigEndian.PutUint16(marshalledData, uint16(*c))
	return marshalledData, nil
}

// Unmarshal decodes a 2-byte big-endian representation into the Class receiver.
// It returns an error if the input slice is not exactly 2 bytes.
func (c *Class) Unmarshal(data []byte) (int, error) {
	if len(data) != 2 {
		return 0, fmt.Errorf("invalid length: got %d bytes, want 2 bytes", len(data))
	}

	bytesRead := 0
	*c = Class(binary.BigEndian.Uint16(data[0:2]))
	bytesRead += 2

	return bytesRead, nil
}

// String returns a string representation of the class, including the QU flag if present.
func (c Class) String() string {
	parts := []string{}
	if c.IsUnicastPreferred() {
		parts = append(parts, "UNICAST")
	}
	switch c.BaseClass() {
	case ClassIN:
		parts = append(parts, "IN")
	case ClassCS:
		parts = append(parts, "CS")
	case ClassCH:
		parts = append(parts, "CH")
	case ClassHS:
		parts = append(parts, "HS")
	case ClassNONE:
		parts = append(parts, "NONE")
	case ClassANY:
		parts = append(parts, "ANY")
	default:
		parts = append(parts, "Unknown")
	}
	return strings.Join(parts, "|")
}
