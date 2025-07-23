package authenticate_test

import (
	"bytes"
	"testing"

	"github.com/TheManticoreProject/Manticore/network/smb/smb_v10/spnego/ntlm/message/authenticate"
	"github.com/TheManticoreProject/Manticore/network/smb/smb_v10/spnego/ntlm/message/challenge"
	"github.com/TheManticoreProject/Manticore/network/smb/smb_v10/spnego/ntlm/message/negotiate/flags"
)

func TestMarshalUnmarshal(t *testing.T) {
	// Create a challenge message with some flags
	challengeMsg := &challenge.ChallengeMessage{
		NegotiateFlags: flags.NTLMSSP_NEGOTIATE_UNICODE | flags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY,
	}
	copy(challengeMsg.ServerChallenge[:], []byte{1, 2, 3, 4, 5, 6, 7, 8})

	// Create an authenticate message
	authMsg, err := authenticate.CreateAuthenticateMessage(challengeMsg, "testuser", "testpass", "testdomain", "testworkstation")
	if err != nil {
		t.Fatalf("Failed to create authenticate message: %v", err)
	}

	authMsg.NegotiateFlags = challengeMsg.NegotiateFlags

	// Marshal the message
	data, err := authMsg.Marshal()
	if err != nil {
		t.Fatalf("Failed to marshal: %v", err)
	}

	// Create a new message and unmarshal into it
	unmarshaledMsg := &authenticate.AuthenticateMessage{}
	_, err = unmarshaledMsg.Unmarshal(data)
	if err != nil {
		t.Fatalf("Failed to unmarshal: %v", err)
	}

	// Compare all fields
	if !bytes.Equal(authMsg.LmChallengeResponse, unmarshaledMsg.LmChallengeResponse) {
		t.Error("LmChallengeResponse mismatch")
		t.Errorf("Expected : %v", authMsg.LmChallengeResponse)
		t.Errorf("Actual   : %v", unmarshaledMsg.LmChallengeResponse)
	}
	if !bytes.Equal(authMsg.NtChallengeResponse, unmarshaledMsg.NtChallengeResponse) {
		t.Error("NtChallengeResponse mismatch")
		t.Errorf("Expected : %v", authMsg.NtChallengeResponse)
		t.Errorf("Actual   : %v", unmarshaledMsg.NtChallengeResponse)
	}
	if !bytes.Equal(authMsg.DomainName, unmarshaledMsg.DomainName) {
		t.Error("DomainName mismatch")
		t.Errorf("Expected : %v", authMsg.DomainName)
		t.Errorf("Actual   : %v", unmarshaledMsg.DomainName)
	}
	if !bytes.Equal(authMsg.UserName, unmarshaledMsg.UserName) {
		t.Error("UserName mismatch")
		t.Errorf("Expected : %v", authMsg.UserName)
		t.Errorf("Actual   : %v", unmarshaledMsg.UserName)
	}
	if !bytes.Equal(authMsg.Workstation, unmarshaledMsg.Workstation) {
		t.Error("Workstation mismatch")
		t.Errorf("Expected : %v", authMsg.Workstation)
		t.Errorf("Actual   : %v", unmarshaledMsg.Workstation)
	}
	if !bytes.Equal(authMsg.EncryptedRandomSessionKey, unmarshaledMsg.EncryptedRandomSessionKey) {
		t.Error("EncryptedRandomSessionKey mismatch")
		t.Errorf("Expected : %v", authMsg.EncryptedRandomSessionKey)
		t.Errorf("Actual   : %v", unmarshaledMsg.EncryptedRandomSessionKey)
	}
	if authMsg.NegotiateFlags != unmarshaledMsg.NegotiateFlags {
		t.Error("NegotiateFlags mismatch")
		t.Errorf("Expected : %v", authMsg.NegotiateFlags)
		t.Errorf("Actual   : %v", unmarshaledMsg.NegotiateFlags)
	}

	// Compare DataFields structures
	if authMsg.LmChallengeResponseFields != unmarshaledMsg.LmChallengeResponseFields {
		t.Error("LmChallengeResponseFields mismatch")
		t.Errorf("Expected : %v", authMsg.LmChallengeResponseFields)
		t.Errorf("Actual   : %v", unmarshaledMsg.LmChallengeResponseFields)
	}
	if authMsg.NtChallengeResponseFields != unmarshaledMsg.NtChallengeResponseFields {
		t.Error("NtChallengeResponseFields mismatch")
		t.Errorf("Expected : %v", authMsg.NtChallengeResponseFields)
		t.Errorf("Actual   : %v", unmarshaledMsg.NtChallengeResponseFields)
	}
	if authMsg.DomainNameFields != unmarshaledMsg.DomainNameFields {
		t.Error("DomainNameFields mismatch")
		t.Errorf("Expected : %v", authMsg.DomainNameFields)
		t.Errorf("Actual   : %v", unmarshaledMsg.DomainNameFields)
	}
	if authMsg.UserNameFields != unmarshaledMsg.UserNameFields {
		t.Error("UserNameFields mismatch")
		t.Errorf("Expected : %v", authMsg.UserNameFields)
		t.Errorf("Actual   : %v", unmarshaledMsg.UserNameFields)
	}
	if authMsg.WorkstationFields != unmarshaledMsg.WorkstationFields {
		t.Error("WorkstationFields mismatch")
		t.Errorf("Expected : %v", authMsg.WorkstationFields)
		t.Errorf("Actual   : %v", unmarshaledMsg.WorkstationFields)
	}
	if authMsg.EncryptedRandomSessionKeyFields != unmarshaledMsg.EncryptedRandomSessionKeyFields {
		t.Error("EncryptedRandomSessionKeyFields mismatch")
		t.Errorf("Expected : %v", authMsg.EncryptedRandomSessionKeyFields)
		t.Errorf("Actual   : %v", unmarshaledMsg.EncryptedRandomSessionKeyFields)
	}
}
