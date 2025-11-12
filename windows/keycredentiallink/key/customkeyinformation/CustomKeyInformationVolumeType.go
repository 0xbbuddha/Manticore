package customkeyinformation

import (
	"fmt"
)

// CustomKeyInformationVolumeType represents the volume type.
//
// Sources:
// https://msdn.microsoft.com/en-us/library/mt220496.aspx
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/701a55dc-d062-4032-a2da-dbdfc384c8cf
type CustomKeyInformationVolumeType uint8

const (
	// Volume not specified.
	CustomKeyInformationVolumeType_None CustomKeyInformationVolumeType = 0x00

	// Operating system volume (OSV).
	CustomKeyInformationVolumeType_OSV CustomKeyInformationVolumeType = 0x01

	// Fixed data volume (FDV).
	CustomKeyInformationVolumeType_FDV CustomKeyInformationVolumeType = 0x02

	// Removable data volume (RDV).
	CustomKeyInformationVolumeType_RDV CustomKeyInformationVolumeType = 0x03
)

// Unmarshal parses the provided byte slice into the CustomKeyInformationVolumeType structure.
//
// Parameters:
// - data: A byte slice containing the raw volume type to be parsed.
//
// Returns:
// - The number of bytes read from the data.
// - An error if the parsing fails, otherwise nil.
//
// Note:
// The function expects the byte slice to contain a single byte representing the volume type.
// It extracts the volume type value from the byte slice and assigns it to the CustomKeyInformationVolumeType structure.
func (vt *CustomKeyInformationVolumeType) Unmarshal(data []byte) (int, error) {
	if len(data) < 1 {
		return 0, fmt.Errorf("invalid data length: %d", len(data))
	}

	*vt = CustomKeyInformationVolumeType(data[0])

	if *vt != CustomKeyInformationVolumeType_None && *vt != CustomKeyInformationVolumeType_OSV && *vt != CustomKeyInformationVolumeType_FDV && *vt != CustomKeyInformationVolumeType_RDV {
		return 0, fmt.Errorf("invalid CustomKeyInformationVolumeType: %d", *vt)
	}

	return 1, nil
}

// Marshal returns the raw bytes of the CustomKeyInformationVolumeType structure.
//
// Returns:
// - A byte slice representing the raw bytes of the CustomKeyInformationVolumeType structure.
// - An error if the conversion fails.
func (vt CustomKeyInformationVolumeType) Marshal() ([]byte, error) {
	return []byte{uint8(vt)}, nil
}

// String returns a string representation of the CustomKeyInformationVolumeType.
//
// Returns:
// - A string representing the CustomKeyInformationVolumeType.
func (vt CustomKeyInformationVolumeType) String() string {
	switch vt {
	case CustomKeyInformationVolumeType_None:
		return "None"
	case CustomKeyInformationVolumeType_OSV:
		return "Operating System Volume (OSV)"
	case CustomKeyInformationVolumeType_FDV:
		return "Fixed Data Volume (FDV)"
	case CustomKeyInformationVolumeType_RDV:
		return "Removable Data Volume (RDV)"
	}

	return "Unknown"
}
