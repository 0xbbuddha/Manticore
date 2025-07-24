package ntlmv1

import (
	"bytes"
	"crypto/des"
	"fmt"

	"github.com/TheManticoreProject/Manticore/crypto/lm"
	"github.com/TheManticoreProject/Manticore/crypto/nt"
)

// NTLMv1Ctx represents the components needed for NTLMv1 authentication.
// Source: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/464551a8-9fc4-428e-b3d3-bc5bfb2e73a5
type NTLMv1Ctx struct {
	Username string // Username for authentication
	Password string // Password for authentication
	Domain   string // Domain name

	NTHash []byte // NT hash of the password
	LMHash []byte // LM hash of the password

	ServerChallenge []byte // 8-byte challenge from server
}

// NewNTLMv1CtxWithPassword creates a new NTLMv1 instance with the provided credentials and challenge.
// It calculates both the NT and LM hashes from the provided password.
//
// Parameters:
//   - domain: The domain name
//   - username: The username
//   - password: The plaintext password
//   - serverChallenge: 8-byte challenge from the server
//
// Returns:
//   - *NTLMv1Ctx: The initialized NTLMv1 context
//   - error: If server challenge is not 8 bytes
func NewNTLMv1CtxWithPassword(domain, username, password string, serverChallenge []byte) (*NTLMv1Ctx, error) {
	if len(serverChallenge) != 8 {
		return nil, fmt.Errorf("server challenge must be 8 bytes")
	}

	ntHash := nt.NTHash(password)
	lmHash := lm.LMHash(password)

	ntlm := &NTLMv1Ctx{
		Domain:   domain,
		Username: username,
		Password: password,

		ServerChallenge: serverChallenge,

		NTHash: ntHash[:],
		LMHash: lmHash[:],
	}

	return ntlm, nil
}

// NewNTLMv1CtxWithNTHash creates a new NTLMv1 instance using a pre-computed NT hash.
// The LM hash will be computed from an empty password.
//
// Parameters:
//   - domain: The domain name
//   - username: The username
//   - nthash: The pre-computed NT hash
//   - serverChallenge: 8-byte challenge from the server
//
// Returns:
//   - *NTLMv1Ctx: The initialized NTLMv1 context
//   - error: If server challenge is not 8 bytes
func NewNTLMv1CtxWithNTHash(domain, username string, nthash []byte, serverChallenge []byte) (*NTLMv1Ctx, error) {
	if len(serverChallenge) != 8 {
		return nil, fmt.Errorf("server challenge must be 8 bytes")
	}

	ntlm := &NTLMv1Ctx{
		Domain:   domain,
		Username: username,
		Password: "",

		ServerChallenge: serverChallenge,

		NTHash: nthash,
		LMHash: lm.LMHash(""),
	}

	return ntlm, nil
}

// NewNTLMv1CtxWithLMHash creates a new NTLMv1 instance using a pre-computed LM hash.
// The NT hash will be computed from an empty password.
//
// Parameters:
//   - domain: The domain name
//   - username: The username
//   - lmhash: The pre-computed LM hash
//   - serverChallenge: 8-byte challenge from the server
//
// Returns:
//   - *NTLMv1Ctx: The initialized NTLMv1 context
//   - error: If server challenge is not 8 bytes
func NewNTLMv1CtxWithLMHash(domain, username string, lmhash []byte, serverChallenge []byte) (*NTLMv1Ctx, error) {
	if len(serverChallenge) != 8 {
		return nil, fmt.Errorf("server challenge must be 8 bytes")
	}

	ntHash := nt.NTHash("")

	ntlm := &NTLMv1Ctx{
		Domain:          domain,
		Username:        username,
		Password:        "",
		ServerChallenge: serverChallenge,
		NTHash:          ntHash[:],
		LMHash:          lmhash,
	}

	return ntlm, nil
}

// NewNTLMv1CtxWithHashes creates a new NTLMv1 instance using pre-computed NT and LM hashes.
//
// Parameters:
//   - domain: The domain name
//   - username: The username
//   - lmhash: The pre-computed LM hash
//   - nthash: The pre-computed NT hash
//   - serverChallenge: 8-byte challenge from the server
//
// Returns:
//   - *NTLMv1Ctx: The initialized NTLMv1 context
//   - error: If server challenge is not 8 bytes
func NewNTLMv1CtxWithHashes(domain, username string, lmhash []byte, nthash []byte, serverChallenge []byte) (*NTLMv1Ctx, error) {
	if len(serverChallenge) != 8 {
		return nil, fmt.Errorf("server challenge must be 8 bytes")
	}

	ntlm := &NTLMv1Ctx{
		Domain:          domain,
		Username:        username,
		Password:        "",
		ServerChallenge: serverChallenge,
		NTHash:          nthash,
		LMHash:          lmhash,
	}

	return ntlm, nil
}

// Hash calculates the NTLMv1 response using the NT hash.
//
// The NT hash is split into three 7-byte keys. Each key is adjusted for DES parity
// and used to encrypt the server challenge. The results are concatenated to form
// the final 24-byte response.
//
// Returns:
//   - []byte: The 24-byte NTLMv1 response
//   - error: If NT hash calculation fails or if neither NTHash nor Password is set
func (h *NTLMv1Ctx) Hash() ([]byte, error) {
	// Start with the NT hash of the password
	if len(h.NTHash) == 0 && len(h.Password) == 0 {
		return nil, fmt.Errorf("NTHash and Password are not set")
	}
	if len(h.NTHash) == 0 {
		ntHash := nt.NTHash(h.Password)
		h.NTHash = ntHash[:]
	}

	rawKeys := h.NTHash
	// Pad the hash with zeros to get 21 bytes (3 * 7)
	rawKeys = append(rawKeys, bytes.Repeat([]byte{0}, 21-len(rawKeys))...)

	// Compute block 1
	key1 := rawKeys[0:7]
	key1Adjusted, err := ParityAdjust(key1)
	if err != nil {
		return nil, fmt.Errorf("failed to adjust parity for K1: %v", err)
	}

	block1, err := des.NewCipher(key1Adjusted)
	if err != nil {
		return nil, fmt.Errorf("failed to create DES cipher for block 1: %v", err)
	}

	ct1 := make([]byte, 8)
	block1.Encrypt(ct1, h.ServerChallenge)

	// Compute block 2
	key2 := rawKeys[7:14]
	key2Adjusted, err := ParityAdjust(key2)
	if err != nil {
		return nil, fmt.Errorf("failed to adjust parity for K2: %v", err)
	}

	block2, err := des.NewCipher(key2Adjusted)
	if err != nil {
		return nil, fmt.Errorf("failed to create DES cipher for block 2: %v", err)
	}

	ct2 := make([]byte, 8)
	block2.Encrypt(ct2, h.ServerChallenge)

	// Compute block 3
	key3 := rawKeys[14:21]
	key3Adjusted, err := ParityAdjust(key3)
	if err != nil {
		return nil, fmt.Errorf("failed to adjust parity for K3: %v", err)
	}

	block3, err := des.NewCipher(key3Adjusted)
	if err != nil {
		return nil, fmt.Errorf("failed to create DES cipher for block 3: %v", err)
	}

	ct3 := make([]byte, 8)
	block3.Encrypt(ct3, h.ServerChallenge)

	// Combine the results
	response := append(append(ct1, ct2...), ct3...)

	return response, nil

}

// NTResponse calculates the NT response for NTLMv1 authentication.
//
// The NT response is calculated by encrypting the server challenge with the NT hash
// using DES encryption. The NT hash is split into three 7-byte keys, each adjusted
// for DES parity, and each key is used to encrypt the challenge.
//
// The process:
// 1. Split the NT hash into three 7-byte keys (padding the last key with zeros)
// 2. Adjust each key for DES parity
// 3. Create DES ciphers with each key
// 4. Encrypt the server challenge with each cipher
// 5. Concatenate the results
//
// Returns:
//   - []byte: The 24-byte NT response
//   - error: If key adjustment or encryption fails
func (n *NTLMv1Ctx) NTResponse() ([]byte, error) {
	// Split the NT hash into three 7-byte keys
	key1 := n.NTHash[:7]
	key2 := n.NTHash[7:14]
	key3 := n.NTHash[14:16]
	// Pad the third key to 7 bytes with zeros
	key3 = append(key3, make([]byte, 5)...)

	// Adjust keys for DES parity
	key1, err := ParityAdjust(key1)
	if err != nil {
		return nil, fmt.Errorf("failed to adjust key1 parity: %v", err)
	}
	key2, err = ParityAdjust(key2)
	if err != nil {
		return nil, fmt.Errorf("failed to adjust key2 parity: %v", err)
	}
	key3, err = ParityAdjust(key3)
	if err != nil {
		return nil, fmt.Errorf("failed to adjust key3 parity: %v", err)
	}

	// Create DES ciphers with each key
	cipher1, err := des.NewCipher(key1)
	if err != nil {
		return nil, fmt.Errorf("failed to create DES cipher with key1: %v", err)
	}
	cipher2, err := des.NewCipher(key2)
	if err != nil {
		return nil, fmt.Errorf("failed to create DES cipher with key2: %v", err)
	}
	cipher3, err := des.NewCipher(key3)
	if err != nil {
		return nil, fmt.Errorf("failed to create DES cipher with key3: %v", err)
	}

	// Encrypt the challenge with each cipher
	result1 := make([]byte, 8)
	result2 := make([]byte, 8)
	result3 := make([]byte, 8)
	cipher1.Encrypt(result1, n.ServerChallenge)
	cipher2.Encrypt(result2, n.ServerChallenge)
	cipher3.Encrypt(result3, n.ServerChallenge)

	// Concatenate the results
	ntResponse := append(result1, result2...)
	ntResponse = append(ntResponse, result3...)

	return ntResponse, nil
}

// LMResponse calculates the LM response for NTLMv1 authentication.
//
// The LM response is calculated by encrypting the server challenge with the LM hash
// using DES encryption. The LM hash is split into three 7-byte keys, each adjusted
// for DES parity, and each key is used to encrypt the challenge.
//
// The process:
// 1. Split the LM hash into three 7-byte keys (padding the last key with zeros)
// 2. Adjust each key for DES parity
// 3. Create DES ciphers with each key
// 4. Encrypt the server challenge with each cipher
// 5. Concatenate the results
//
// Returns:
//   - []byte: The 24-byte LM response
//   - error: If key adjustment or encryption fails
func (n *NTLMv1Ctx) LMResponse() ([]byte, error) {
	// Create the LM hash
	lmHash := lm.LMHash(n.Password)

	// Split the LM hash into three 7-byte keys
	key1 := lmHash[:7]
	key2 := lmHash[7:14]
	key3 := lmHash[14:16]
	// Pad the third key to 7 bytes with zeros
	key3 = append(key3, make([]byte, 5)...)

	// Adjust keys for DES parity
	key1, err := ParityAdjust(key1)
	if err != nil {
		return nil, fmt.Errorf("failed to adjust key1 parity: %v", err)
	}
	key2, err = ParityAdjust(key2)
	if err != nil {
		return nil, fmt.Errorf("failed to adjust key2 parity: %v", err)
	}
	key3, err = ParityAdjust(key3)
	if err != nil {
		return nil, fmt.Errorf("failed to adjust key3 parity: %v", err)
	}

	// Create DES ciphers with each key
	cipher1, err := des.NewCipher(key1)
	if err != nil {
		return nil, fmt.Errorf("failed to create DES cipher with key1: %v", err)
	}
	cipher2, err := des.NewCipher(key2)
	if err != nil {
		return nil, fmt.Errorf("failed to create DES cipher with key2: %v", err)
	}
	cipher3, err := des.NewCipher(key3)
	if err != nil {
		return nil, fmt.Errorf("failed to create DES cipher with key3: %v", err)
	}

	// Encrypt the challenge with each cipher
	result1 := make([]byte, 8)
	result2 := make([]byte, 8)
	result3 := make([]byte, 8)
	cipher1.Encrypt(result1, n.ServerChallenge)
	cipher2.Encrypt(result2, n.ServerChallenge)
	cipher3.Encrypt(result3, n.ServerChallenge)

	// Concatenate the results
	lmResponse := append(result1, result2...)
	lmResponse = append(lmResponse, result3...)

	return lmResponse, nil
}
