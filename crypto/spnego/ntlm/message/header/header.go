package header

import (
	"encoding/binary"
	"fmt"

	"github.com/TheManticoreProject/Manticore/network/smb/smb_v10/spnego/ntlm/message/types"
)

// NTLM signature
var NTLM_SIGNATURE = [8]byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0}

// Header is the header of an NTLM message
type Header struct {
	// Signature (8 bytes): An 8-byte character array that MUST contain the ASCII string ('N', 'T', 'L', 'M', 'S', 'S', 'P', '\0').
	Signature [8]byte

	// MessageType (4 bytes): A 32-bit unsigned integer that indicates the message type.
	MessageType types.MessageType
}

// Marshal serializes the Header into a byte slice
func (m *Header) Marshal() ([]byte, error) {
	marshalledData := []byte{}

	// Write signature
	marshalledData = append(marshalledData, m.Signature[:]...)

	// Write message type
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, uint32(m.MessageType))
	marshalledData = append(marshalledData, buf...)

	return marshalledData, nil
}

// Unmarshal deserializes a byte slice into a Header
func (m *Header) Unmarshal(data []byte) (int, error) {
	if len(data) < 12 {
		return 0, fmt.Errorf("data too short to be a valid Header")
	}

	copy(m.Signature[:], data[:8])

	m.MessageType = types.MessageType(binary.LittleEndian.Uint32(data[8:12]))

	return 12, nil
}

// GetType returns the message type
func (m *Header) GetType() types.MessageType {
	return m.MessageType
}

// SetType sets the message type
func (m *Header) SetType(messageType types.MessageType) {
	m.MessageType = messageType
}

// GetSignature returns the signature
func (m *Header) GetSignature() [8]byte {
	return m.Signature
}

// SetSignature sets the signature
func (m *Header) SetSignature(signature [8]byte) {
	m.Signature = signature
}
