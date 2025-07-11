package key

import "fmt"

type KeyUsage struct {
	Value uint8

	// Internal
	RawBytes     []byte
	RawBytesSize uint8
}

const (
	// Key Usage
	// See: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d4b9b239-dbe8-4475-b6f9-745612c64ed0

	// Admin key (pin-reset key)
	KeyUsage_AdminKey uint8 = 0

	// NGC key attached to a user object (KEY_USAGE_NGC)
	KeyUsage_NGC uint8 = 0x01

	// Transport key attached to a device object
	KeyUsage_STK uint8 = 0x02

	// BitLocker recovery key
	KeyUsage_BitlockerRecovery uint8 = 0x03

	// Unrecognized key usage
	KeyUsage_Other uint8 = 0x04

	// Fast IDentity Online Key (KEY_USAGE_FIDO)
	KeyUsage_FIDO uint8 = 0x07

	// File Encryption Key (KEY_USAGE_FEK)
	KeyUsage_FEK uint8 = 0x08

	// DPAPI Key
	// TODO: The DPAPI enum needs to be mapped to a proper integer value.
	KeyUsage_DPAPI uint8 = 0x09
)

// Unmarshal parses the key usage from a byte array.
//
// Parameters:
// - data: A byte array representing the key usage.
//
// Returns:
// - The number of bytes read from the data.
// - An error if the parsing fails, otherwise nil.
//
// Note:
// The function expects the byte slice to contain a single byte representing the key usage.
// It extracts the key usage value from the byte slice and assigns it to the KeyUsage structure.
func (ku *KeyUsage) Unmarshal(data []byte) (int, error) {
	if len(data) < 1 {
		return 0, fmt.Errorf("invalid data length: %d", len(data))
	}

	ku.RawBytes = data[:1]
	ku.RawBytesSize = 1

	ku.Value = data[0]

	return 1, nil
}

// Marshal returns the raw bytes of the KeyUsage structure.
//
// Returns:
// - A byte slice representing the raw bytes of the KeyUsage structure.
// - An error if the conversion fails.
func (ku *KeyUsage) Marshal() ([]byte, error) {
	ku.RawBytes = []byte{ku.Value}
	ku.RawBytesSize = 1

	return ku.RawBytes, nil
}

// String returns a string representation of the key usage.
//
// Returns:
// - A string representing the key usage.
func (ku *KeyUsage) String() string {
	switch ku.Value {
	case KeyUsage_AdminKey:
		return "AdminKey"
	case KeyUsage_NGC:
		return "New Generation Credential (NGC)"
	case KeyUsage_STK:
		return "Smart Token Key (STK)"
	case KeyUsage_BitlockerRecovery:
		return "Bitlocker Recovery"
	case KeyUsage_Other:
		return "Other"
	case KeyUsage_FIDO:
		return "Fast IDentity Online (FIDO)"
	case KeyUsage_FEK:
		return "File Encryption Key (FEK)"
	case KeyUsage_DPAPI:
		return "Data Protection API (DPAPI)"
	}

	return fmt.Sprintf("Unknown KeyUsage: %d", ku.Value)
}
