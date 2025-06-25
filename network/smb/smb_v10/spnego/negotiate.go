package spnego

import (
	"errors"
	"fmt"

	"github.com/TheManticoreProject/Manticore/network/smb/smb_v10/spnego/ntlm/message/negotiate"
	"github.com/TheManticoreProject/Manticore/network/smb/smb_v10/spnego/ntlm/message/negotiate/flags"
	"github.com/TheManticoreProject/Manticore/network/smb/smb_v10/spnego/ntlm/version"
)

// CreateNegotiateToken creates the initial SPNEGO token with NTLM negotiate message
// Parameters:
//   - ctx: The authentication context containing domain, username, password, and other settings
//
// Returns:
//   - []byte: The SPNEGO token containing the NTLM negotiate message
//   - error: An error if token creation fails
func (ctx *AuthContext) CreateNegotiateToken(negotiateFlags flags.NegotiateFlags, version *version.Version) ([]byte, error) {
	switch ctx.Type {
	case AuthTypeNTLM:
		// Create NTLM NEGOTIATE message
		ntlmNegotiate, err := negotiate.CreateNegotiateMessage(ctx.Domain, ctx.Workstation, negotiateFlags, version)
		if err != nil {
			return nil, fmt.Errorf("failed to create NTLM NEGOTIATE message: %v", err)
		}

		ntlmNegotiateBytes, err := ntlmNegotiate.Marshal()
		if err != nil {
			return nil, fmt.Errorf("failed to marshal NTLM NEGOTIATE message: %v", err)
		}

		// Wrap in SPNEGO
		return CreateNegTokenInit(ntlmNegotiateBytes)

	case AuthTypeKerberos:
		return nil, errors.New("kerberos authentication is not yet implemented")

	default:
		return nil, fmt.Errorf("unsupported authentication type: %v", ctx.Type)
	}
}
