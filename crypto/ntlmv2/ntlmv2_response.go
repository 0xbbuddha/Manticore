package ntlmv2

import (
	"encoding/hex"
	"fmt"
	"strings"
)

type NTLMv2Response struct {
	Username string // Username for authentication
	Domain   string // Domain name

	ServerChallenge     [8]byte  // 8-byte challenge from server
	LmChallengeResponse [24]byte // 24-byte LM challenge response
	NtChallengeResponse [24]byte // 24-byte NT challenge response
}

// NewNTLMv2Response creates a new NTLMv2 response
//
// Parameters:
//   - username: The username
//   - domain: The domain name
//   - serverChallenge: The 8-byte server challenge
//   - lmChallengeResponse: The 24-byte LM challenge response
func NewNTLMv2Response(username, domain string, serverChallenge [8]byte, lmChallengeResponse [24]byte, ntChallengeResponse [24]byte) *NTLMv2Response {
	return &NTLMv2Response{
		Username:            username,
		Domain:              domain,
		ServerChallenge:     serverChallenge,
		LmChallengeResponse: lmChallengeResponse,
		NtChallengeResponse: ntChallengeResponse,
	}
}

// HashcatString converts the NTLMv2 response to a Hashcat string
//
// Returns:
//   - The Hashcat string
//   - An error if the conversion fails
func (r *NTLMv2Response) HashcatString() (string, error) {
	hashcatString := fmt.Sprintf(
		"%s::%s:%s:%s:%s",
		r.Username,
		r.Domain,
		strings.ToUpper(hex.EncodeToString(r.ServerChallenge[:])),
		strings.ToUpper(hex.EncodeToString(r.LmChallengeResponse[:])),
		strings.ToUpper(hex.EncodeToString(r.NtChallengeResponse[:])),
	)

	return hashcatString, nil
}

// String returns the NTLMv2 response as a string
//
// Returns:
//   - The NTLMv2 response as a string
//   - An error if the conversion fails
func (r *NTLMv2Response) String() string {
	hashcatString, err := r.HashcatString()
	if err != nil {
		return ""
	}
	return hashcatString
}
