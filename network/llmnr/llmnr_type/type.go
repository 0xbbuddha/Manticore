package llmnr_type

import (
	"encoding/binary"
	"fmt"
)

// Type represents the type field in an LLMNR question.
//
// LLMNR reuses DNS RR TYPE codes for question types (e.g., A, AAAA).
// Only a subset is typically used in practice (A and AAAA), but we include
// common DNS types for completeness.
type Type uint16

// LLMNR Question Types (DNS-compatible)
const (
	TypeA     Type = 1   // IPv4 address
	TypeNS    Type = 2   // Authoritative name server
	TypeCNAME Type = 5   // Canonical name for an alias
	TypeSOA   Type = 6   // Start of authority
	TypePTR   Type = 12  // Domain name pointer
	TypeMX    Type = 15  // Mail exchange
	TypeTXT   Type = 16  // Text strings
	TypeAAAA  Type = 28  // IPv6 address
	TypeSRV   Type = 33  // Service locator
	TypeOPT   Type = 41  // OPT pseudo-RR, RFC 2671
	TypeAXFR  Type = 252 // Transfer of entire zone
	TypeALL   Type = 255 // All records
)

// Marshal encodes the Type into a 2-byte big-endian representation.
func (t *Type) Marshal() ([]byte, error) {
	marshalledData := make([]byte, 2)
	binary.BigEndian.PutUint16(marshalledData, uint16(*t))
	return marshalledData, nil
}

// Unmarshal decodes a 2-byte big-endian representation into the Type receiver.
// It returns an error if the input slice is not exactly 2 bytes.
func (t *Type) Unmarshal(data []byte) (int, error) {
	if len(data) != 2 {
		return 0, fmt.Errorf("invalid length: got %d bytes, want 2 bytes", len(data))
	}

	bytesRead := 0
	*t = Type(binary.BigEndian.Uint16(data[0:2]))
	bytesRead += 2

	return bytesRead, nil
}

// String returns a string representation of the question type.
func (t Type) String() string {
	switch t {
	case TypeA:
		return "A"
	case TypeNS:
		return "NS"
	case TypeCNAME:
		return "CNAME"
	case TypeSOA:
		return "SOA"
	case TypePTR:
		return "PTR"
	case TypeMX:
		return "MX"
	case TypeTXT:
		return "TXT"
	case TypeAAAA:
		return "AAAA"
	case TypeSRV:
		return "SRV"
	case TypeOPT:
		return "OPT"
	case TypeAXFR:
		return "AXFR"
	case TypeALL:
		return "ALL"
	}
	return "Unknown"
}
