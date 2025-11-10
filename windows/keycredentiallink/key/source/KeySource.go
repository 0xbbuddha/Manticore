package source

import (
	"fmt"
)

// KeySource represents the source of the key.
// Sources:
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d4b9b239-dbe8-4475-b6f9-745612c64ed0?redirectedfrom=MSDN
// https://msdn.microsoft.com/en-us/library/mt220501.aspx
type KeySource struct {
	Value uint8
}

const (
	// On Premises Key Trust
	KeySource_AD uint8 = 0x00

	// Hybrid Azure AD Key Trust
	KeySource_AzureAD uint8 = 0x01
)

// String returns the string representation of the KeySource.
//
// Returns:
// - A string representing the key source.
func (ks *KeySource) String() string {
	switch ks.Value {
	case KeySource_AD:
		return "Active Directory (AD)"
	case KeySource_AzureAD:
		return "Azure Active Directory (AAD)"
	default:
		return fmt.Sprintf("Unknown KeySource: %d", int(ks.Value))
	}
}

// Unmarshal parses the key source from a byte array.
//
// Parameters:
// - data: A byte array representing the key source.
//
// Returns:
// - A KeySource object.
func (ks *KeySource) Unmarshal(data []byte) (int, error) {
	if len(data) < 1 {
		return 0, fmt.Errorf("invalid data length: %d", len(data))
	}

	ks.Value = data[0]

	return 1, nil
}

// Marshal returns the raw bytes of the KeySource structure.
//
// Returns:
// - A byte slice representing the raw bytes of the KeySource structure.
// - An error if the conversion fails.
func (ks *KeySource) Marshal() ([]byte, error) {
	return []byte{ks.Value}, nil
}
