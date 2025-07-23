package spnego

import (
	"errors"
	"fmt"

	"github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/message/authenticate"
	"github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/message/challenge"
)

// CreateAuthenticateTokenFromChallengeToken processes the server's challenge token and creates an authenticate token
// Parameters:
//   - challengeToken: The SPNEGO token containing the server's challenge
//
// Returns:
//   - []byte: The SPNEGO token containing the authenticate message
//   - error: An error if token processing fails
func (ctx *AuthContext) CreateAuthenticateTokenFromChallengeToken(challengeToken []byte) ([]byte, error) {
	// Parse the SPNEGO token
	resp := NegTokenResp{}
	_, err := resp.Unmarshal(challengeToken)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SPNEGO token: %v", err)
	}

	// Check if the server accepted our mechanism
	if resp.NegState == NegStateReject {
		return nil, errors.New("server rejected authentication")
	}

	// Extract the inner token
	innerToken, err := ExtractNTLMToken(challengeToken)
	if err != nil {
		return nil, fmt.Errorf("failed to extract inner token: %v", err)
	}

	switch ctx.Type {
	case AuthTypeNTLM:
		return ctx.processChallengeInnerTokenNTLM(innerToken)
	case AuthTypeKerberos:
		return ctx.processChallengeInnerTokenKerberos(innerToken)
	default:
		return nil, fmt.Errorf("unsupported authentication type: %v", ctx.Type)
	}
}

// processChallengeInnerTokenNTLM processes the NTLM challenge token and creates an NTLM authenticate token
// Parameters:
//   - innerToken: The inner NTLM challenge token bytes
//
// Returns:
//   - []byte: The SPNEGO token containing the NTLM authenticate message
//   - error: An error if token processing fails
func (ctx *AuthContext) processChallengeInnerTokenNTLM(innerToken []byte) ([]byte, error) {
	// Parse the NTLM CHALLENGE message
	challenge := &challenge.ChallengeMessage{}
	_, err := challenge.Unmarshal(innerToken)
	if err != nil {
		return nil, fmt.Errorf("failed to parse NTLM CHALLENGE message: %v", err)
	}

	// Store the challenge for later use
	ctx.NTLMChallenge = challenge

	// Create NTLM AUTHENTICATE message
	ntlmAuth, err := authenticate.CreateAuthenticateMessage(challenge, ctx.Username, ctx.Password, ctx.Domain, ctx.Workstation)
	if err != nil {
		return nil, fmt.Errorf("failed to create NTLM AUTHENTICATE message: %v", err)
	}

	ntlmAuthBytes, err := ntlmAuth.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal NTLM AUTHENTICATE message: %v", err)
	}

	// Wrap in SPNEGO
	return CreateNegTokenInit(ntlmAuthBytes)
}

// processChallengeInnerTokenKerberos processes the Kerberos challenge token and creates a Kerberos authenticate token
// Parameters:
//   - innerToken: The inner Kerberos challenge token bytes
//
// Returns:
//   - []byte: The SPNEGO token containing the Kerberos authenticate message
//   - error: An error if token processing fails
func (ctx *AuthContext) processChallengeInnerTokenKerberos(innerToken []byte) ([]byte, error) {
	// TODO: Implement kerberos authentication
	return nil, errors.New("kerberos authentication is not yet implemented")
}
