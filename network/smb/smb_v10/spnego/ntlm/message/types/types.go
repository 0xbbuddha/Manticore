package types

import "fmt"

type MessageType uint32

// NTLM message types
// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b34032e5-3aae-4bc6-84c3-c6d80eadf7f2
const (
	// NEGOTIATE_MESSAGE_TYPE is the message type for the NTLM negotiate message
	// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/b34032e5-3aae-4bc6-84c3-c6d80eadf7f2
	NEGOTIATE_MESSAGE_TYPE MessageType = 0x00000001

	// CHALLENGE_MESSAGE_TYPE is the message type for the NTLM challenge message
	// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/801a4681-8809-4be9-ab0d-61dcfe762786
	CHALLENGE_MESSAGE_TYPE MessageType = 0x00000002

	// AUTHENTICATE_MESSAGE_TYPE is the message type for the NTLM authenticate message
	// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/033d32cc-88f9-4483-9bf2-b273055038ce
	AUTHENTICATE_MESSAGE_TYPE MessageType = 0x00000003
)

// String returns the string representation of the message type
func (mt MessageType) String() string {
	if mt == NEGOTIATE_MESSAGE_TYPE {
		return "NEGOTIATE"
	} else if mt == CHALLENGE_MESSAGE_TYPE {
		return "CHALLENGE"
	} else if mt == AUTHENTICATE_MESSAGE_TYPE {
		return "AUTHENTICATE"
	}
	return fmt.Sprintf("UNKNOWN_MESSAGE_TYPE(0x%08x)", uint32(mt))
}
