package key

import "fmt"

// CustomKeyInformationFlags represents custom key flags.
//
// See: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/701a55dc-d062-4032-a2da-dbdfc384c8cf
type CustomKeyInformationFlags struct {
	Value uint8
	Name  []string

	// Internal
	RawBytes     []byte
	RawBytesSize uint32
}

const (
	// No flags specified.
	CustomKeyInformationFlags_None uint8 = 0

	// Reserved for future use. (CUSTOMKEYINFO_FLAGS_ATTESTATION)
	CustomKeyInformationFlags_Attestation uint8 = 0x01

	// During creation of this key, the requesting client authenticated using
	// only a single credential. (CUSTOMKEYINFO_FLAGS_MFA_NOT_USED)
	CustomKeyInformationFlags_MFANotUsed uint8 = 0x02
)

// Unmarshal parses the provided byte slice into the CustomKeyInformationFlags structure.
//
// Parameters:
// - value: A byte slice containing the raw key flags to be parsed.
//
// Returns:
// - The number of bytes read from the data.
// - An error if the parsing fails, otherwise nil.
//
// Note:
// The function expects the byte slice to contain a single byte representing the key flags.
// It extracts the flags value from the byte slice and assigns it to the CustomKeyInformationFlags structure.
func (kf *CustomKeyInformationFlags) Unmarshal(data []byte) (int, error) {
	if len(data) < 1 {
		return 0, fmt.Errorf("invalid data length: %d", len(data))
	}

	kf.RawBytes = data
	kf.RawBytesSize = uint32(len(data))

	kf.Value = data[0]

	kf.Name = []string{}
	if kf.Value&CustomKeyInformationFlags_Attestation == CustomKeyInformationFlags_Attestation {
		kf.Name = append(kf.Name, "Attestation")
	}
	if kf.Value&CustomKeyInformationFlags_MFANotUsed == CustomKeyInformationFlags_MFANotUsed {
		kf.Name = append(kf.Name, "MFA not used")
	}

	if len(kf.Name) == 0 {
		kf.Name = append(kf.Name, "None")
	}

	return 1, nil
}
