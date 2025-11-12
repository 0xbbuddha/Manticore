package keycredentiallink

import (
	"fmt"
)

/*
Key Credential Link Entry Identifier

Describes the data stored in the Value field.
https://msdn.microsoft.com/en-us/library/mt220499.aspx
*/
type KEYCREDENTIALLINK_ENTRY_IDENTIFIER uint8

// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a99409ea-4982-4f72-b7ef-8596013a36c7
const (
	// A SHA256 hash of the Value field of the KeyMaterial entry.
	KEYCREDENTIALLINK_ENTRY_IDENTIFIER_KeyID KEYCREDENTIALLINK_ENTRY_IDENTIFIER = 0x01

	// A SHA256 hash of all entries following this entry.
	KEYCREDENTIALLINK_ENTRY_IDENTIFIER_KeyHash KEYCREDENTIALLINK_ENTRY_IDENTIFIER = 0x02

	// Key material of the credential.
	KEYCREDENTIALLINK_ENTRY_IDENTIFIER_KeyMaterial KEYCREDENTIALLINK_ENTRY_IDENTIFIER = 0x03

	// Key Usage
	KEYCREDENTIALLINK_ENTRY_IDENTIFIER_KeyUsage KEYCREDENTIALLINK_ENTRY_IDENTIFIER = 0x04

	// Key Source
	KEYCREDENTIALLINK_ENTRY_IDENTIFIER_KeySource KEYCREDENTIALLINK_ENTRY_IDENTIFIER = 0x05

	// Device Identifier
	KEYCREDENTIALLINK_ENTRY_IDENTIFIER_DeviceId KEYCREDENTIALLINK_ENTRY_IDENTIFIER = 0x06

	// Custom key information.
	KEYCREDENTIALLINK_ENTRY_IDENTIFIER_CustomKeyInformation KEYCREDENTIALLINK_ENTRY_IDENTIFIER = 0x07

	// The approximate time this key was last used, in FILETIME format.
	KEYCREDENTIALLINK_ENTRY_IDENTIFIER_KeyApproximateLastLogonTimeStamp KEYCREDENTIALLINK_ENTRY_IDENTIFIER = 0x08

	// The approximate time this key was created, in FILETIME format.
	KEYCREDENTIALLINK_ENTRY_IDENTIFIER_KeyCreationTime KEYCREDENTIALLINK_ENTRY_IDENTIFIER = 0x09
)

// Unmarshal parses the provided byte slice into the KEYCREDENTIALLINK_ENTRY_IDENTIFIER structure.
//
// Parameters:
// - data: A byte slice containing the raw key credential entry type to be parsed.
//
// Returns:
// - The number of bytes read from the data.
func (k *KEYCREDENTIALLINK_ENTRY_IDENTIFIER) Unmarshal(data []byte) (int, error) {
	*k = KEYCREDENTIALLINK_ENTRY_IDENTIFIER(data[0])

	return 1, nil
}

// Marshal returns the raw bytes of the KEYCREDENTIALLINK_ENTRY_IDENTIFIER structure.
//
// Returns:
// - A byte slice representing the raw bytes of the KEYCREDENTIALLINK_ENTRY_IDENTIFIER structure.
func (k *KEYCREDENTIALLINK_ENTRY_IDENTIFIER) Marshal() ([]byte, error) {
	return []byte{uint8(*k)}, nil
}

// String returns a string representation of the KEYCREDENTIALLINK_ENTRY_IDENTIFIER.
//
// Returns:
// - A string representing the KEYCREDENTIALLINK_ENTRY_IDENTIFIER.
func (k *KEYCREDENTIALLINK_ENTRY_IDENTIFIER) String() string {
	switch *k {
	case KEYCREDENTIALLINK_ENTRY_IDENTIFIER_KeyID:
		return "KeyID"
	case KEYCREDENTIALLINK_ENTRY_IDENTIFIER_KeyHash:
		return "KeyHash"
	case KEYCREDENTIALLINK_ENTRY_IDENTIFIER_KeyMaterial:
		return "KeyMaterial"
	case KEYCREDENTIALLINK_ENTRY_IDENTIFIER_KeyUsage:
		return "KeyUsage"
	case KEYCREDENTIALLINK_ENTRY_IDENTIFIER_KeySource:
		return "KeySource"
	case KEYCREDENTIALLINK_ENTRY_IDENTIFIER_DeviceId:
		return "DeviceId"
	case KEYCREDENTIALLINK_ENTRY_IDENTIFIER_CustomKeyInformation:
		return "CustomKeyInformation"
	case KEYCREDENTIALLINK_ENTRY_IDENTIFIER_KeyApproximateLastLogonTimeStamp:
		return "KeyApproximateLastLogonTimeStamp"
	case KEYCREDENTIALLINK_ENTRY_IDENTIFIER_KeyCreationTime:
		return "KeyCreationTime"
	default:
		return fmt.Sprintf("Unknown KEYCREDENTIALLINK_ENTRY_IDENTIFIER: %d", *k)
	}
}

// Equal checks if two KEYCREDENTIALLINK_ENTRY_IDENTIFIER structures are equal.
//
// Parameters:
// - other: A KEYCREDENTIALLINK_ENTRY_IDENTIFIER structure to compare to.
//
// Returns:
// - True if the two KEYCREDENTIALLINK_ENTRY_IDENTIFIER structures are equal, false otherwise.
func (k *KEYCREDENTIALLINK_ENTRY_IDENTIFIER) Equal(other *KEYCREDENTIALLINK_ENTRY_IDENTIFIER) bool {
	return *k == *other
}
