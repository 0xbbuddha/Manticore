package types_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/message/types"
)

func TestMessageTypeString(t *testing.T) {
	tests := []struct {
		messageType types.MessageType
		expected    string
	}{
		{
			messageType: types.MESSAGE_TYPE_NEGOTIATE,
			expected:    "NEGOTIATE",
		},
		{
			messageType: types.MESSAGE_TYPE_CHALLENGE,
			expected:    "CHALLENGE",
		},
		{
			messageType: types.MESSAGE_TYPE_AUTHENTICATE,
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
