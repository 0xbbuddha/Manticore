package customkeyinformation

import "fmt"

type SupportsNotification bool

const (
	SupportsNotification_TRUE  SupportsNotification = true
	SupportsNotification_FALSE SupportsNotification = false
)

// Marshal returns the raw bytes of the SupportsNotification structure.
//
// Returns:
// - A byte slice representing the raw bytes of the SupportsNotification structure.
// - An error if the conversion fails.
func (sn SupportsNotification) Marshal() ([]byte, error) {
	if sn {
		return []byte{1}, nil
	}
	return []byte{0}, nil
}

// Unmarshal parses the provided byte slice into the SupportsNotification structure.
//
// Parameters:
// - data: A byte slice containing the raw supports notification to be parsed.
//
// Returns:
// - The number of bytes read from the data.
// - An error if the parsing fails, otherwise nil.
func (sn *SupportsNotification) Unmarshal(data []byte) (int, error) {
	if len(data) < 1 {
		return 0, fmt.Errorf("invalid data length: %d", len(data))
	}

	*sn = SupportsNotification(data[0] != 0)

	return 1, nil
}

// String returns a string representation of the SupportsNotification.
//
// Returns:
// - A string representing the SupportsNotification.
func (sn SupportsNotification) String() string {
	if sn {
		return "True"
	}
	return "False"
}
