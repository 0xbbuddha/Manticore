package message_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/message"
	"github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/message/authenticate"
	"github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/message/challenge"
	"github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/message/negotiate"
)

func TestMessageInterface(t *testing.T) {
	// Test that all message types implement the Message interface
	var _ message.NTLMSSPMessage = &negotiate.NegotiateMessage{}
	var _ message.NTLMSSPMessage = &challenge.ChallengeMessage{}
	var _ message.NTLMSSPMessage = &authenticate.AuthenticateMessage{}
}
