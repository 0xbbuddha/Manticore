package keycredential

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

/*
Key Credential Link Entry Identifier

Describes the data stored in the Value field.
https://msdn.microsoft.com/en-us/library/mt220499.aspx
*/
type KeyCredentialEntryType struct {
	Value uint8

	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

const (
	// A SHA256 hash of the Value field of the KeyMaterial entry.
	KeyCredentialEntryType_KeyID uint8 = 0x01

	// A SHA256 hash of all entries following this entry.
	KeyCredentialEntryType_KeyHash uint8 = 0x02

	// Key material of the credential.
	KeyCredentialEntryType_KeyMaterial uint8 = 0x03

	// Key Usage
	KeyCredentialEntryType_KeyUsage uint8 = 0x04

	// Key Source
	KeyCredentialEntryType_KeySource uint8 = 0x05

	// Device Identifier
	KeyCredentialEntryType_DeviceId uint8 = 0x06

	// Custom key information.
	KeyCredentialEntryType_CustomKeyInformation uint8 = 0x07

	// The approximate time this key was last used, in FILETIME format.
	KeyCredentialEntryType_KeyApproximateLastLogonTimeStamp uint8 = 0x08

	// The approximate time this key was created, in FILETIME format.
	KeyCredentialEntryType_KeyCreationTime uint8 = 0x09
)

// Unmarshal parses the provided byte slice into the KeyCredentialEntryType structure.
//
// Parameters:
// - data: A byte slice containing the raw key credential entry type to be parsed.
//
// Returns:
// - The number of bytes read from the data.
func (k *KeyCredentialEntryType) Unmarshal(data []byte) (int, error) {
	k.RawBytes = data[:1]
	k.RawBytesSize = 1

	k.Value = data[0]

	return 1, nil
}

// Marshal returns the raw bytes of the KeyCredentialEntryType structure.
//
// Returns:
// - A byte slice representing the raw bytes of the KeyCredentialEntryType structure.
func (k *KeyCredentialEntryType) Marshal() ([]byte, error) {
	return []byte{k.Value}, nil
}

// String returns a string representation of the KeyCredentialEntryType.
//
// Returns:
// - A string representing the KeyCredentialEntryType.
func (k *KeyCredentialEntryType) String() string {
	switch k.Value {
	case KeyCredentialEntryType_KeyID:
		return "KeyID"
	case KeyCredentialEntryType_KeyHash:
		return "KeyHash"
	case KeyCredentialEntryType_KeyMaterial:
		return "KeyMaterial"
	case KeyCredentialEntryType_KeyUsage:
		return "KeyUsage"
	case KeyCredentialEntryType_KeySource:
		return "KeySource"
	case KeyCredentialEntryType_DeviceId:
		return "DeviceId"
	case KeyCredentialEntryType_CustomKeyInformation:
		return "CustomKeyInformation"
	case KeyCredentialEntryType_KeyApproximateLastLogonTimeStamp:
		return "KeyApproximateLastLogonTimeStamp"
	case KeyCredentialEntryType_KeyCreationTime:
		return "KeyCreationTime"
	default:
		return fmt.Sprintf("Unknown KeyCredentialEntryType: %d", k.Value)
	}
}

// WriteEntry writes a typed KeyCredentialEntry to the buffer.
//
// Parameters:
// - buffer: A pointer to a bytes.Buffer object.
// - entryType: A KeyCredentialEntryType object representing the type of the entry.
// - data: A byte slice representing the data to be written.
func WriteEntry(buffer *bytes.Buffer, entryType KeyCredentialEntryType, data []byte) {
	binary.Write(buffer, binary.LittleEndian, uint16(len(data)))
	entryTypeBytes, err := entryType.Marshal()
	if err != nil {
		return
	}
	buffer.Write(entryTypeBytes)
	buffer.Write(data)
}
