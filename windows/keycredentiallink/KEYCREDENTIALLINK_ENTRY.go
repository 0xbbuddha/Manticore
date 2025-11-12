package keycredentiallink

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"
)

// 2.2.20.3 KEYCREDENTIALLINK_ENTRY
//
// The KEYCREDENTIALLINK_ENTRY structure describes various aspects of a single credential.
//
// Fields:
// - EntryType: A KeyCredentialEntryType object representing the type of the entry.
// - Data: A byte slice containing the data of the entry.
//
// Methods:
// - Unmarshal: Unmarshals the entry from a byte slice.
// - Marshal: Marshals the entry to a byte slice.
// - String: Returns a string representation of the entry.
//
// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/7dd677bd-9315-403c-8104-b6270350139e
type KEYCREDENTIALLINK_ENTRY struct {
	// A 16-bit unsigned integer that specifies the length of the Value field.
	Length uint16
	// An 8-bit unsigned integer that specifies the type of data that is stored in the Value field.
	Identifier KEYCREDENTIALLINK_ENTRY_IDENTIFIER
	// A series of bytes whose size and meaning are defined by the Identifier field.
	Value []byte
}

// Unmarshal unmarshals the entry from a byte slice.
//
// Parameters:
// - data: A byte slice containing the data of the entry.
//
// Returns:
// - An error if the unmarshalling fails, otherwise nil.
func (e *KEYCREDENTIALLINK_ENTRY) Unmarshal(data []byte) (int, error) {
	bytesRead := 0

	e.Length = binary.LittleEndian.Uint16(data[bytesRead:2])
	bytesRead += 2

	identifierBytesRead, err := e.Identifier.Unmarshal(data[bytesRead : bytesRead+1])
	if err != nil {
		return bytesRead, err
	}
	bytesRead += identifierBytesRead

	e.Value = data[bytesRead : bytesRead+int(e.Length)]
	bytesRead += int(e.Length)

	return bytesRead, nil
}

// Marshal marshals the entry to a byte slice.
//
// Parameters:
// - None
//
// Returns:
// - A byte slice containing the marshalled entry.
func (e *KEYCREDENTIALLINK_ENTRY) Marshal() ([]byte, error) {
	marshalledData := make([]byte, 0)

	marshalledData = append(marshalledData, binary.LittleEndian.AppendUint16(marshalledData, e.Length)...)

	identifierBytes, err := e.Identifier.Marshal()
	if err != nil {
		return nil, err
	}
	marshalledData = append(marshalledData, identifierBytes...)

	marshalledData = append(marshalledData, e.Value...)

	return marshalledData, nil
}

// String returns a string representation of the entry.
//
// Parameters:
// - None
//
// Returns:
// - A string representation of the entry.
func (e *KEYCREDENTIALLINK_ENTRY) String() string {
	return ""
}

// Describe prints the KEYCREDENTIALLINK_ENTRY structure to the console.
//
// Parameters:
// - indent: The number of spaces to indent the output.
func (e *KEYCREDENTIALLINK_ENTRY) Describe(indent int) {
	indentPrompt := strings.Repeat(" │ ", indent)
	fmt.Printf("%s<\x1b[93mKEYCREDENTIALLINK_ENTRY\x1b[0m>\n", indentPrompt)
	fmt.Printf("%s │ \x1b[93mLength\x1b[0m: 0x%04x (%d)\n", indentPrompt, e.Length, e.Length)
	fmt.Printf("%s │ \x1b[93mIdentifier\x1b[0m: 0x%02x (%s)\n", indentPrompt, uint8(e.Identifier), e.Identifier.String())
	fmt.Printf("%s │ \x1b[93mValue\x1b[0m: %s\n", indentPrompt, hex.EncodeToString(e.Value))
	fmt.Printf("%s └───\n", indentPrompt)
}
