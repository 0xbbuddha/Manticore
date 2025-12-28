package ntlmv2

import (
	"crypto/hmac"
	"crypto/md5"
	"errors"
	"strings"
	"time"

	"github.com/TheManticoreProject/Manticore/crypto/lm"
	"github.com/TheManticoreProject/Manticore/crypto/nt"
	"github.com/TheManticoreProject/Manticore/encoding/utf16"
)

// NTLMv2 represents the components needed for NTLMv2 authentication
// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3
type NTLMv2Ctx struct {
	Domain   string
	Username string
	Password string

	ServerChallenge [8]byte
	ClientChallenge [8]byte

	NTHash [16]byte
	LMHash [16]byte

	ResponseKeyNT [16]byte
	ResponseKeyLM [16]byte
}

// NewNTLMv2CtxWithPassword creates a new NTLMv2 instance with the provided credentials and challenges
//
// Parameters:
//   - domain: The domain name
//   - username: The username
//   - password: The plaintext password
//   - serverChallenge: The 8-byte server challenge
//   - clientChallenge: The 8-byte client challenge
func NewNTLMv2CtxWithPassword(domain, username, password string, serverChallenge, clientChallenge [8]byte) (*NTLMv2Ctx, error) {
	ntHash := nt.NTHash(password)
	return NewNTLMv2CtxWithNTHash(domain, username, ntHash, serverChallenge, clientChallenge)
}

// NewNTLMv2CtxWithNTHash creates a new NTLMv2 instance with the provided credentials and challenges
//
// Parameters:
//   - domain: The domain name
//   - username: The username
//   - nthash: The 16-byte NT hash
//   - serverChallenge: The 8-byte server challenge
//   - clientChallenge: The 8-byte client challenge
func NewNTLMv2CtxWithNTHash(domain, username string, nthash [16]byte, serverChallenge, clientChallenge [8]byte) (*NTLMv2Ctx, error) {
	if len(serverChallenge) != 8 {
		return nil, errors.New("server challenge must be 8 bytes")
	}

	if len(clientChallenge) != 8 {
		return nil, errors.New("client challenge must be 8 bytes")
	}

	ntlm := &NTLMv2Ctx{
		Domain:   domain,
		Username: username,
		Password: "",

		ServerChallenge: serverChallenge,
		ClientChallenge: clientChallenge,

		NTHash: nthash,
		LMHash: lm.LMHash(""),
	}

	// Calculate the ResponseKeyNT (HMAC-MD5 of NT-Hash with username and domain)
	usernameUpper := strings.ToUpper(username)
	domainUpper := strings.ToUpper(domain)
	identity := utf16.EncodeUTF16LE(usernameUpper + domainUpper)

	h := hmac.New(md5.New, ntlm.NTHash[:])
	h.Write(identity)
	copy(ntlm.ResponseKeyNT[:], h.Sum(nil))

	return ntlm, nil
}

// ComputeResponse computes the NTLMv2 response for a given domain, username, password,
// server challenge, and client challenge.
//
// Parameters:
//   - domain: The domain name
//   - username: The username
//   - password: The plaintext password
//   - serverChallenge: The 8-byte server challenge
//   - clientChallenge: The 8-byte client challenge
//
// Returns:
//   - The NTLMv2 response as a byte slice
//   - An error if the computation fails
func (ntlm *NTLMv2Ctx) ComputeResponse(ResponseKeyNT, ResponseKeyLM, ServerChallenge, ClientChallenge []byte, Time time.Time, ServerName []byte) ([]byte, error) {
	// Special case for anonymous authentication
	if len(ResponseKeyNT) == 0 && len(ResponseKeyLM) == 0 {
		return []byte{0}, nil
	}

	// Create temp blob
	// Set temp to ConcatenationOf(Responserversion, HiResponserversion, Z(6), Time, ClientChallenge, Z(4), ServerName, Z(4))
	temp := make([]byte, 0)
	temp = append(temp, 0x01)               // Response version
	temp = append(temp, 0x01)               // Hi Response version
	temp = append(temp, make([]byte, 6)...) // Z(6)
	// temp = append(temp, Time...)            // Timestamp
	temp = append(temp, ClientChallenge...) // Client challenge
	temp = append(temp, make([]byte, 4)...) // Z(4)
	temp = append(temp, ServerName...)      // Server name
	temp = append(temp, make([]byte, 4)...) // Z(4)

	// Calculate NT proof string
	// Set NTProofStr to HMAC_MD5(ResponseKeyNT, ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge,temp))
	ntProofStrCtx := hmac.New(md5.New, append(ResponseKeyNT, append(ServerChallenge, temp...)...))
	ntProofStr := ntProofStrCtx.Sum(nil)
	NtChallengeResponse := append(ntProofStr, temp...)

	// Calculate LM response
	// Set LMResponse to HMAC_MD5(ResponseKeyLM, ConcatenationOf(CHALLENGE_MESSAGE.ServerChallenge, CHALLENGE_MESSAGE.ClientChallenge))
	lmHmacCtx := hmac.New(md5.New, append(ResponseKeyLM, append(ServerChallenge, ClientChallenge...)...))
	lmChallengeResponse := lmHmacCtx.Sum(nil)

	// Combine NT proof string with temp blob for final NT response
	challengeResponse := append(NtChallengeResponse, lmChallengeResponse...)

	return challengeResponse, nil

}

// LMResponse computes the LM response for the NTLMv2 authentication
//
// Returns:
//   - The LM response as a byte slice
//   - An error if the computation fails
func (ntlm *NTLMv2Ctx) LMResponse() ([]byte, error) {
	if len(ntlm.ServerChallenge) != 8 {
		return nil, errors.New("server challenge must be 8 bytes")
	}

	if len(ntlm.ClientChallenge) != 8 {
		return nil, errors.New("client challenge must be 8 bytes")
	}

	// Calculate the LM response (HMAC-MD5 of NTHash with server challenge and client challenge)
	lm := hmac.New(md5.New, ntlm.NTHash[:])
	lm.Write(ntlm.ServerChallenge[:])
	lm.Write(ntlm.ClientChallenge[:])
	lmResponse := lm.Sum(nil)

	return lmResponse, nil
}

// NTResponse computes the NT response for the NTLMv2 authentication
//
// Returns:
//   - The NT response as a byte slice
//   - An error if the computation fails
func (ntlm *NTLMv2Ctx) NTResponse() ([]byte, error) {
	if len(ntlm.ServerChallenge) != 8 {
		return nil, errors.New("server challenge must be 8 bytes")
	}

	if len(ntlm.ClientChallenge) != 8 {
		return nil, errors.New("client challenge must be 8 bytes")
	}

	// Calculate the NT response (HMAC-MD5 of NTHash with server challenge and client challenge)
	nt := hmac.New(md5.New, ntlm.NTHash[:])
	nt.Write(ntlm.ServerChallenge[:])
	nt.Write(ntlm.ClientChallenge[:])
	ntResponse := nt.Sum(nil)

	return ntResponse, nil
}

// NTOWFv2 computes the NTOWFv2 hash for a given password, username, and domain
// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3
//
// Returns:
//   - The NTOWFv2 hash as a byte slice
//   - An error if the computation fails
func NTOWFv2(Passwd, User, UserDomain string) []byte {
	// Convert password to UTF16-LE bytes
	passwdBytes := []byte(Passwd)
	if !utf16.IsUTF16LE(passwdBytes) {
		passwdBytes = utf16.EncodeUTF16LE(Passwd)
	}
	ntHash := nt.NTHash(Passwd)

	// Convert username and domain to uppercase UTF16-LE bytes
	upperUser := strings.ToUpper(User)
	userDomainBytes := utf16.EncodeUTF16LE(upperUser + UserDomain)

	// Calculate HMAC-MD5
	hmacMd5 := hmac.New(md5.New, ntHash[:])
	hmacMd5.Write(userDomainBytes)
	return hmacMd5.Sum(nil)
}

// LMOWFv2 computes the LMOWFv2 hash for a given password, username, and domain
// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/5e550938-91d4-459f-b67d-75d70009e3f3
//
// Returns:
//   - The LMOWFv2 hash as a byte slice
//   - An error if the computation fails
func LMOWFv2(Passwd, User, UserDomain string) []byte {
	return NTOWFv2(Passwd, User, UserDomain)
}
