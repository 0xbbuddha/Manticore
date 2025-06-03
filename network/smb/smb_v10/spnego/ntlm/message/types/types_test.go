package types_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/network/smb/smb_v10/spnego/ntlm/message/types"
)

func TestMessageTypeString(t *testing.T) {
	tests := []struct {
		messageType types.MessageType
		expected    string
	}{
		{
			messageType: types.NEGOTIATE_MESSAGE_TYPE,
			expected:    "NEGOTIATE",
		},
		{
			messageType: types.CHALLENGE_MESSAGE_TYPE,
			expected:    "CHALLENGE",
		},
		{
			messageType: types.AUTHENTICATE_MESSAGE_TYPE,
			expected:    "AUTHENTICATE",
		},
		{
			messageType: types.MessageType(0x00000004),
			expected:    "UNKNOWN_MESSAGE_TYPE(0x00000004)",
		},
	}

	for _, test := range tests {
		result := test.messageType.String()
		if result != test.expected {
			t.Errorf("Expected %s, got %s", test.expected, result)
		}
	}
}
