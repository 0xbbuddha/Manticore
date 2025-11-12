package customkeyinformation

import "fmt"

// CUSTOMKEYINFO_FLAGS represents custom key flags.
//
// See: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/701a55dc-d062-4032-a2da-dbdfc384c8cf
type CUSTOMKEYINFO_FLAGS uint8

const (
	// No flags specified.
	CUSTOMKEYINFO_FLAGS_NONE CUSTOMKEYINFO_FLAGS = 0

	// Reserved for future use. (CUSTOMKEYINFO_FLAGS_ATTESTATION)
	CUSTOMKEYINFO_FLAGS_ATTESTATION CUSTOMKEYINFO_FLAGS = 0x01

	// During creation of this key, the requesting client authenticated using
	// only a single credential. (CUSTOMKEYINFO_FLAGS_MFA_NOT_USED)
	CUSTOMKEYINFO_FLAGS_MFA_NOT_USED CUSTOMKEYINFO_FLAGS = 0x02
)

// Unmarshal parses the provided byte slice into the CUSTOMKEYINFO_FLAGS structure.
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
// It extracts the flags value from the byte slice and assigns it to the CUSTOMKEYINFO_FLAGS structure.
func (kf *CUSTOMKEYINFO_FLAGS) Unmarshal(data []byte) (int, error) {
	if len(data) < 1 {
		return 0, fmt.Errorf("invalid data length: %d", len(data))
	}

	*kf = CUSTOMKEYINFO_FLAGS(data[0])

	if *kf != CUSTOMKEYINFO_FLAGS_ATTESTATION &&
		*kf != CUSTOMKEYINFO_FLAGS_MFA_NOT_USED &&
		*kf != CUSTOMKEYINFO_FLAGS_NONE &&
		*kf != CUSTOMKEYINFO_FLAGS_ATTESTATION|CUSTOMKEYINFO_FLAGS_MFA_NOT_USED {
		return 0, fmt.Errorf("invalid CUSTOMKEYINFO_FLAGS: %d", *kf)
	}

	return 1, nil
}

// Marshal returns the raw bytes of the CUSTOMKEYINFO_FLAGS structure.
//
// Returns:
// - A byte slice representing the raw bytes of the CUSTOMKEYINFO_FLAGS structure.
// - An error if the conversion fails.
func (kf CUSTOMKEYINFO_FLAGS) Marshal() ([]byte, error) {
	return []byte{uint8(kf)}, nil
}

func (kf CUSTOMKEYINFO_FLAGS) String() string {
	switch kf {
	case CUSTOMKEYINFO_FLAGS_NONE:
		return "None"
	case CUSTOMKEYINFO_FLAGS_ATTESTATION:
		return "Attestation"
	case CUSTOMKEYINFO_FLAGS_MFA_NOT_USED:
		return "MFA not used"
	case CUSTOMKEYINFO_FLAGS_MFA_NOT_USED | CUSTOMKEYINFO_FLAGS_ATTESTATION:
		return "Attestation | MFA not used"
	}
	return "Unknown"
}

// NewCUSTOMKEYINFO_FLAGS returns a pointer to a flags value.
func NewCUSTOMKEYINFO_FLAGS(v CUSTOMKEYINFO_FLAGS) *CUSTOMKEYINFO_FLAGS {
	f := v
	return &f
}

// Set sets the provided mask on the flags.
func (kf *CUSTOMKEYINFO_FLAGS) Set(mask CUSTOMKEYINFO_FLAGS) {
	*kf |= mask
}

// Has returns true if the provided mask is set.
func (kf CUSTOMKEYINFO_FLAGS) Has(mask CUSTOMKEYINFO_FLAGS) bool {
	return kf&mask == mask
}
