package client

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"
	"time"

	ntlm_authenticate "github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/message/authenticate"
	ntlm_challenge "github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/message/challenge"
	ntlm_negotiate "github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/message/negotiate"
	ntlm_flags "github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/message/negotiate/flags"
	"github.com/TheManticoreProject/Manticore/crypto/nt"
	"github.com/TheManticoreProject/Manticore/encoding/utf16"
	"github.com/TheManticoreProject/Manticore/windows/credentials"
)

// ntlmMicOffset is the byte offset of the MIC field within a serialized AUTHENTICATE_MESSAGE.
// Layout: Signature(8) + MessageType(4) + 6×DataFields(8) + NegotiateFlags(4) + Version(8) = 72.
const ntlmMicOffset = 72

// ntlmEncryptedBoundary is the MIME multipart boundary used for WinRM encrypted messages.
const ntlmEncryptedBoundary = "Encrypted Boundary"

// ntlmEncryptedContentType is the HTTP Content-Type for WinRM NTLM-encrypted SOAP messages.
const ntlmEncryptedContentType = `multipart/encrypted;protocol="application/HTTP-SPNEGO-session-encrypted";boundary="Encrypted Boundary"`

// Session represents an authenticated WinRM session over an HTTP connection.
type Session struct {
	// Client is the WinRM client owning this session.
	Client *Client

	// Credentials are the Windows credentials used for NTLM authentication.
	Credentials *credentials.Credentials

	// authenticated indicates whether the underlying HTTP connection has been
	// authenticated via the NTLM handshake.
	authenticated bool

	// NTLM message-level sealing state.
	// These fields are populated after a successful NTLM handshake.
	//
	// signKey is the client-to-server NTLM signing key derived from the exported session key.
	signKey []byte
	// sealHandle is the stateful RC4 cipher used to seal (encrypt) outgoing SOAP messages.
	sealHandle *rc4.Cipher
	// serverSignKey is the server-to-client signing key.
	serverSignKey []byte
	// serverSealHandle is the stateful RC4 cipher used to unseal (decrypt) incoming SOAP messages.
	serverSealHandle *rc4.Cipher
	// seqNum is the outgoing message sequence number, incremented after each sent message.
	seqNum uint32
	// serverSeqNum is the incoming message sequence number, incremented after each received message.
	serverSeqNum uint32
}

// wsmanIdentifyBody is a minimal WS-Management Identify request used to validate credentials.
// It requires no shell, no selector set, and no complex WS-Addressing headers — just auth.
const wsmanIdentifyBody = `<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" xmlns:wsmid="http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd"><s:Header/><s:Body><wsmid:Identify/></s:Body></s:Envelope>`

// SessionSetup authenticates the session against the WinRM server using NTLM.
//
// It performs the full NTLM negotiate-challenge-authenticate handshake immediately
// using a lightweight WS-Management Identify request. A successful return (nil error)
// means the credentials are valid and the connection is ready.
//
// Returns:
//   - error: An error if the transport is not connected or if authentication fails.
func (s *Session) SessionSetup() error {
	if !s.Client.Transport.IsConnected() {
		return fmt.Errorf("transport is not connected")
	}

	s.authenticated = false

	_, _, _, err := s.sendWithNTLM([]byte(wsmanIdentifyBody))
	if err != nil {
		return err
	}

	return nil
}

// sendWithNTLM performs the raw NTLM negotiate-challenge-authenticate handshake, pairing it
// with the supplied SOAP body so the authenticated response IS the WS-Management response.
//
// WinRM over HTTP requires NTLM with SIGN + SEAL + KEY_EXCH negotiated so that all SOAP
// messages are protected with NTLM message-level sealing (RC4 + HMAC-MD5). The first SOAP
// body is therefore sealed as part of the authenticate step itself.
//
// Parameters:
//   - body ([]byte): The SOAP XML request body to pair with the NTLM Authenticate token.
//
// Returns:
//   - int: The HTTP response status code from the authenticated request.
//   - map[string][]string: The HTTP response headers.
//   - []byte: The decrypted SOAP XML response body.
//   - error: An error if any step of the handshake fails.
func (s *Session) sendWithNTLM(body []byte) (int, map[string][]string, []byte, error) {
	// WinRM requires SIGN + SEAL + KEY_EXCH so the server also sets these flags in the
	// challenge, which makes message sealing obligatory for both sides.
	negotiate_flags := ntlm_flags.NegotiateFlags(
		ntlm_flags.NTLMSSP_NEGOTIATE_UNICODE |
			ntlm_flags.NTLMSSP_REQUEST_TARGET |
			ntlm_flags.NTLMSSP_NEGOTIATE_SIGN |
			ntlm_flags.NTLMSSP_NEGOTIATE_SEAL |
			ntlm_flags.NTLMSSP_NEGOTIATE_NTLM |
			ntlm_flags.NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
			ntlm_flags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
			ntlm_flags.NTLMSSP_NEGOTIATE_TARGET_INFO |
			ntlm_flags.NTLMSSP_NEGOTIATE_KEY_EXCH |
			ntlm_flags.NTLMSSP_NEGOTIATE_128 |
			ntlm_flags.NTLMSSP_NEGOTIATE_56,
	)

	// Step 1: Build raw NTLM Type1 (Negotiate) token.
	negotiate_msg, err := ntlm_negotiate.CreateNegotiateMessage("", "", negotiate_flags, nil)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to create NTLM negotiate message: %v", err)
	}

	negotiate_bytes, err := negotiate_msg.Marshal()
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to marshal NTLM negotiate message: %v", err)
	}

	negotiate_b64 := base64.StdEncoding.EncodeToString(negotiate_bytes)

	// Step 2: Send NTLM Negotiate token with an empty body — server responds with 401 +
	// NTLM Challenge. The real SOAP body is only sent in the authenticated step below.
	step1_status, step1_headers, _, err := s.Client.Transport.Post(map[string]string{
		"Authorization": "Negotiate " + negotiate_b64,
	}, []byte{})
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to send NTLM negotiate request: %v", err)
	}

	if step1_status != 401 {
		return 0, nil, nil, fmt.Errorf("expected HTTP 401 for NTLM challenge, got %d", step1_status)
	}

	// Step 3: Extract raw NTLM Type2 (Challenge) from WWW-Authenticate header.
	www_auth_values, ok := step1_headers["Www-Authenticate"]
	if !ok || len(www_auth_values) == 0 {
		return 0, nil, nil, fmt.Errorf("server did not return a WWW-Authenticate header")
	}

	challenge_b64 := ""
	for _, header_value := range www_auth_values {
		if strings.HasPrefix(header_value, "Negotiate ") {
			challenge_b64 = strings.TrimPrefix(header_value, "Negotiate ")
			break
		}
	}
	if challenge_b64 == "" {
		return 0, nil, nil, fmt.Errorf("server did not return an NTLM challenge in WWW-Authenticate header")
	}

	challenge_bytes, err := base64.StdEncoding.DecodeString(challenge_b64)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to decode NTLM challenge token: %v", err)
	}

	// Step 4: Parse raw NTLM Type2 (Challenge) message directly.
	challenge_msg := &ntlm_challenge.ChallengeMessage{}
	if _, err := challenge_msg.Unmarshal(challenge_bytes); err != nil {
		return 0, nil, nil, fmt.Errorf("failed to unmarshal NTLM challenge message: %v", err)
	}

	// Step 5: Build raw NTLM Type3 (Authenticate) message and derive the exported session key.
	// The exported session key is needed to set up the NTLM sealing context before sending
	// the first sealed SOAP body in step 6.
	var auth_bytes []byte
	var exported_session_key []byte

	if (challenge_msg.NegotiateFlags & ntlm_flags.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY) != 0 {
		auth_bytes, exported_session_key, err = s.buildNTLMv2AuthBytes(negotiate_bytes, challenge_bytes, challenge_msg)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("failed to build NTLMv2 authenticate message: %v", err)
		}
	} else {
		auth_msg, err := ntlm_authenticate.CreateAuthenticateMessage(
			challenge_msg,
			s.Credentials.Username,
			s.Credentials.Password,
			s.Credentials.Domain,
			"",
		)
		if err != nil {
			return 0, nil, nil, fmt.Errorf("failed to create NTLM authenticate message: %v", err)
		}
		auth_bytes, err = auth_msg.Marshal()
		if err != nil {
			return 0, nil, nil, fmt.Errorf("failed to marshal NTLM authenticate message: %v", err)
		}
		exported_session_key = nil
	}

	// Step 6: Derive sealing keys and initialise the RC4 handles.
	// This must happen before wrapping the first SOAP body because the sealed body is sent
	// alongside the Authenticate token in the same HTTP request.
	if exported_session_key != nil {
		if err := s.setupSecurityKeys(exported_session_key); err != nil {
			return 0, nil, nil, fmt.Errorf("failed to set up NTLM security keys: %v", err)
		}
	}

	// Step 7: Seal the SOAP body.
	// WinRM requires the SOAP body to be wrapped in a multipart/encrypted MIME envelope
	// even in the authenticate step, because sealing is negotiated at the NTLM level.
	wrapped_body, err := s.wrapNTLM(body)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to seal SOAP body for authenticate step: %v", err)
	}

	auth_b64 := base64.StdEncoding.EncodeToString(auth_bytes)

	// Step 8: Send NTLM Authenticate token paired with the sealed SOAP request.
	step2_status, step2_headers, step2_body, err := s.Client.Transport.Post(map[string]string{
		"Authorization": "Negotiate " + auth_b64,
		"Content-Type":  ntlmEncryptedContentType,
	}, wrapped_body)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("failed to send NTLM authenticate request: %v", err)
	}

	if step2_status == 401 {
		return 0, nil, nil, fmt.Errorf("authentication failed: server rejected credentials")
	}

	// Step 9: Decrypt the server response. If unwrapping fails the response may be a plain
	// error (e.g. HTTP 400 Bad Request before sealing), which still means auth succeeded.
	plain_body, err := s.unwrapNTLM(step2_body)
	if err != nil {
		plain_body = step2_body
	}

	s.authenticated = true

	return step2_status, step2_headers, plain_body, nil
}

// setupSecurityKeys derives the NTLM signing and sealing keys from the exported session key
// and initialises the stateful RC4 cipher handles for both directions.
//
// Key derivation follows MS-NLMP section 3.4.5.1 (SIGNKEY) and 3.4.5.3 (SEALKEY) with
// Extended Session Security and 128-bit key strength.
//
// Parameters:
//   - exported_session_key ([]byte): The 16-byte exported session key from authentication.
//
// Returns:
//   - error: An error if any key derivation or cipher initialisation fails.
func (s *Session) setupSecurityKeys(exported_session_key []byte) error {
	sign_magic_c2s := []byte("session key to client-to-server signing key magic constant\x00")
	seal_magic_c2s := []byte("session key to client-to-server sealing key magic constant\x00")
	sign_magic_s2c := []byte("session key to server-to-client signing key magic constant\x00")
	seal_magic_s2c := []byte("session key to server-to-client sealing key magic constant\x00")

	// Client-to-server signing key.
	h := md5.New()
	h.Write(exported_session_key)
	h.Write(sign_magic_c2s)
	s.signKey = h.Sum(nil)

	// Client-to-server sealing key (128-bit: use full exported session key).
	h = md5.New()
	h.Write(exported_session_key)
	h.Write(seal_magic_c2s)
	seal_key_c2s := h.Sum(nil)

	var err error
	s.sealHandle, err = rc4.NewCipher(seal_key_c2s)
	if err != nil {
		return fmt.Errorf("failed to initialise client-to-server RC4 seal handle: %v", err)
	}

	// Server-to-client signing key.
	h = md5.New()
	h.Write(exported_session_key)
	h.Write(sign_magic_s2c)
	s.serverSignKey = h.Sum(nil)

	// Server-to-client sealing key.
	h = md5.New()
	h.Write(exported_session_key)
	h.Write(seal_magic_s2c)
	seal_key_s2c := h.Sum(nil)

	s.serverSealHandle, err = rc4.NewCipher(seal_key_s2c)
	if err != nil {
		return fmt.Errorf("failed to initialise server-to-client RC4 seal handle: %v", err)
	}

	s.seqNum = 0
	s.serverSeqNum = 0

	return nil
}

// wrapNTLM seals a plain SOAP body with NTLM message-level security and wraps it in the
// multipart/encrypted MIME envelope required by WinRM over HTTP.
//
// The sealing process (MS-NLMP section 3.4.3) uses the stateful RC4 sealHandle and the
// HMAC-MD5 signKey to produce a 16-byte NTLMSSP_MESSAGE_SIGNATURE. The RC4 state is shared
// between encryption and checksum encryption so both must be applied in the correct order.
//
// Parameters:
//   - body ([]byte): The plain SOAP XML body to protect.
//
// Returns:
//   - []byte: The multipart/encrypted MIME envelope containing the sealed message.
//   - error: An error if signing or encryption fails.
func (s *Session) wrapNTLM(body []byte) ([]byte, error) {
	if s.sealHandle == nil {
		return nil, fmt.Errorf("NTLM seal handle not initialised")
	}

	seq_bytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(seq_bytes, s.seqNum)

	// Compute HMAC-MD5(signKey, SeqNum || plaintext)[0:8].
	mac := hmac.New(md5.New, s.signKey)
	mac.Write(seq_bytes)
	mac.Write(body)
	checksum := mac.Sum(nil)[:8]

	// RC4-encrypt the body first, then RC4-encrypt the checksum with the same continuing stream.
	encrypted_body := make([]byte, len(body))
	s.sealHandle.XORKeyStream(encrypted_body, body)

	encrypted_checksum := make([]byte, 8)
	s.sealHandle.XORKeyStream(encrypted_checksum, checksum)

	// Build NTLMSSP_MESSAGE_SIGNATURE: Version(4) + EncryptedChecksum(8) + SeqNum(4).
	sig := make([]byte, 16)
	binary.LittleEndian.PutUint32(sig[0:4], 1)
	copy(sig[4:12], encrypted_checksum)
	copy(sig[12:16], seq_bytes)

	s.seqNum++

	// Assemble the multipart/encrypted MIME envelope.
	// Format: boundary + metadata + boundary + octet-stream header +
	//         [4-byte sig_len][signature][encrypted body] + closing boundary.
	original_len := len(body)

	var buf bytes.Buffer
	fmt.Fprintf(&buf,
		"--%s\r\n\tContent-Type: application/HTTP-SPNEGO-session-encrypted\r\n\tOriginalContent: type=application/soap+xml;charset=UTF-8;Length=%d\r\n--%s\r\n\tContent-Type: application/octet-stream\r\n",
		ntlmEncryptedBoundary, original_len, ntlmEncryptedBoundary,
	)

	sig_len := make([]byte, 4)
	binary.LittleEndian.PutUint32(sig_len, 16)
	buf.Write(sig_len)
	buf.Write(sig)
	buf.Write(encrypted_body)

	fmt.Fprintf(&buf, "--%s--\r\n", ntlmEncryptedBoundary)

	return buf.Bytes(), nil
}

// unwrapNTLM extracts and decrypts the SOAP body from a multipart/encrypted MIME envelope
// returned by the WinRM server.
//
// The server uses the server-to-client sealing keys (separate direction from client-to-server),
// so a dedicated serverSealHandle and serverSignKey are used. The RC4 state advances across
// calls, matching the server's stream position.
//
// Parameters:
//   - data ([]byte): The raw HTTP response body (multipart/encrypted MIME).
//
// Returns:
//   - []byte: The decrypted plain SOAP XML body.
//   - error: An error if the MIME format is invalid or decryption fails.
func (s *Session) unwrapNTLM(data []byte) ([]byte, error) {
	if s.serverSealHandle == nil {
		return nil, fmt.Errorf("NTLM server seal handle not initialised")
	}

	// Locate the binary part: starts after "\tContent-Type: application/octet-stream\r\n".
	// WinRM uses tab-indented MIME headers (as per pypsrp/spnego reference implementation).
	octet_marker := []byte("\tContent-Type: application/octet-stream\r\n")
	idx := bytes.Index(data, octet_marker)
	if idx < 0 {
		return nil, fmt.Errorf("missing octet-stream part in server response")
	}

	binary_data := data[idx+len(octet_marker):]

	// Strip the trailing MIME closing boundary (immediately follows the binary data, no leading CRLF).
	trailer := []byte("--" + ntlmEncryptedBoundary + "--\r\n")
	if bytes.HasSuffix(binary_data, trailer) {
		binary_data = binary_data[:len(binary_data)-len(trailer)]
	}

	if len(binary_data) < 4 {
		return nil, fmt.Errorf("encrypted response too short")
	}

	header_len := int(binary.LittleEndian.Uint32(binary_data[:4]))
	if len(binary_data) < 4+header_len {
		return nil, fmt.Errorf("encrypted response truncated")
	}

	sig := binary_data[4 : 4+header_len]
	encrypted_body := binary_data[4+header_len:]

	// RC4-decrypt the body (serverSealHandle state advances by len(encrypted_body)).
	plaintext := make([]byte, len(encrypted_body))
	s.serverSealHandle.XORKeyStream(plaintext, encrypted_body)

	// Advance the serverSealHandle state by 8 bytes to match the server's checksum encryption.
	// The server RC4-encrypted its HMAC checksum after encrypting the body; we must consume
	// the same 8 bytes from our mirrored RC4 stream.
	_ = sig
	dummy := make([]byte, 8)
	s.serverSealHandle.XORKeyStream(dummy, dummy)

	s.serverSeqNum++

	return plaintext, nil
}

// buildNTLMv2AuthBytes computes a proper NTLMv2 AUTHENTICATE_MESSAGE and returns its
// serialized form together with the exported session key needed for sealing key derivation.
//
// Implements MS-NLMP section 3.3.2 (NTLMv2 response) and section 3.1.5.1.2 (MIC):
//
//   - ResponseKeyNT = HMAC-MD5(NTHash, UTF16-LE(upper(username) + upper(domain)))
//   - NTProofStr    = HMAC-MD5(ResponseKeyNT, ServerChallenge || blob)
//   - NTChallengeResponse = NTProofStr || blob
//   - LmChallengeResponse = Z(24) when MsvAvTimestamp present, else HMAC+ClientChallenge
//
// When KEY_EXCH is negotiated, a random session key is generated and RC4-encrypted with
// the session base key; the ExportedSessionKey equals the random session key.
// When the challenge TargetInfo contains MsvAvTimestamp, a Message Integrity Code (MIC)
// is computed over all three NTLM messages using the ExportedSessionKey.
//
// Parameters:
//   - negotiate_bytes ([]byte): The raw NTLM Type1 (Negotiate) message bytes.
//   - challenge_bytes ([]byte): The raw NTLM Type2 (Challenge) message bytes.
//   - challenge_msg (*ntlm_challenge.ChallengeMessage): The parsed NTLM Type2 challenge.
//
// Returns:
//   - []byte: The serialized NTLM AUTHENTICATE_MESSAGE bytes.
//   - []byte: The 16-byte exported session key for sealing key derivation.
//   - error: An error if response computation or serialisation fails.
func (s *Session) buildNTLMv2AuthBytes(negotiate_bytes, challenge_bytes []byte, challenge_msg *ntlm_challenge.ChallengeMessage) ([]byte, []byte, error) {
	username := s.Credentials.Username
	password := s.Credentials.Password
	domain := s.Credentials.Domain

	// ResponseKeyNT = HMAC-MD5(NTHash, UTF16-LE(upper(username) + upper(domain)))
	nt_hash := nt.NTHash(password)
	response_key_nt_mac := hmac.New(md5.New, nt_hash[:])
	response_key_nt_mac.Write(utf16.EncodeUTF16LE(strings.ToUpper(username) + strings.ToUpper(domain)))
	response_key_nt := response_key_nt_mac.Sum(nil)

	// Client challenge: 8 random bytes.
	client_challenge := make([]byte, 8)
	if _, err := rand.Read(client_challenge); err != nil {
		return nil, nil, fmt.Errorf("failed to generate client challenge: %v", err)
	}

	// Use the server's MsvAvTimestamp when present (MS-NLMP 3.1.5.1.2), otherwise use
	// the current Windows FILETIME (100-ns intervals since Jan 1, 1601).
	timestamp := ntlmTargetInfoGetAvValue(challenge_msg.TargetInfo, 0x0007)
	if len(timestamp) != 8 {
		windows_filetime := (uint64(time.Now().Unix()) + 116444736000) * 10000000
		timestamp = make([]byte, 8)
		binary.LittleEndian.PutUint64(timestamp, windows_filetime)
	}

	// Build the effective TargetInfo for the blob: copy the challenge TargetInfo then
	// add MsvAvFlags=0x0002 (MIC present, MS-NLMP 2.2.2.1 bit 1).
	// The addition is inserted before the EOL marker.
	needs_mic := ntlmTargetInfoHasAvId(challenge_msg.TargetInfo, 0x0007)
	effective_target_info := ntlmBuildBlobTargetInfo(challenge_msg.TargetInfo, needs_mic)

	// NTLMv2 blob (temp):
	//   RespType(1) | HiRespType(1) | Reserved(2) | Reserved(4) | Timestamp(8) | ClientChallenge(8) | Reserved(4) | TargetInfo(var) | Reserved(4)
	blob := make([]byte, 0, 28+len(effective_target_info))
	blob = append(blob, 0x01, 0x01)             // RespType, HiRespType
	blob = append(blob, 0x00, 0x00)             // Reserved1
	blob = append(blob, 0x00, 0x00, 0x00, 0x00) // Reserved2
	blob = append(blob, timestamp...)           // Timestamp (server's MsvAvTimestamp or current time)
	blob = append(blob, client_challenge...)    // ClientChallenge
	blob = append(blob, 0x00, 0x00, 0x00, 0x00) // Reserved3
	blob = append(blob, effective_target_info...) // TargetInfo (with MsvAvFlags)
	blob = append(blob, 0x00, 0x00, 0x00, 0x00) // Reserved4

	// NTProofStr = HMAC-MD5(ResponseKeyNT, ServerChallenge || blob)
	proof_mac := hmac.New(md5.New, response_key_nt)
	proof_mac.Write(challenge_msg.ServerChallenge[:])
	proof_mac.Write(blob)
	nt_proof_str := proof_mac.Sum(nil)

	// NTChallengeResponse = NTProofStr || blob
	nt_challenge_response := append(nt_proof_str, blob...)

	// LmChallengeResponse: per MS-NLMP 3.1.5.1.2, when MsvAvTimestamp is present the
	// LmChallengeResponse MUST be set to Z(24) (24 zero bytes). Only compute the real
	// HMAC when MsvAvTimestamp is absent (no MIC scenario).
	var lm_challenge_response []byte
	if needs_mic {
		lm_challenge_response = make([]byte, 24)
	} else {
		lm_mac := hmac.New(md5.New, response_key_nt)
		lm_mac.Write(challenge_msg.ServerChallenge[:])
		lm_mac.Write(client_challenge)
		lm_challenge_response = append(lm_mac.Sum(nil), client_challenge...)
	}

	// SessionBaseKey = HMAC-MD5(ResponseKeyNT, NTProofStr)
	session_key_mac := hmac.New(md5.New, response_key_nt)
	session_key_mac.Write(nt_proof_str)
	session_base_key := session_key_mac.Sum(nil)

	// KEY_EXCH: generate a random session key, RC4-encrypt it with SessionBaseKey.
	// ExportedSessionKey = RandomSessionKey (the decrypted form of EncryptedRandomSessionKey).
	var encrypted_random_session_key []byte
	var exported_session_key []byte

	if (challenge_msg.NegotiateFlags & ntlm_flags.NTLMSSP_NEGOTIATE_KEY_EXCH) != 0 {
		random_session_key := make([]byte, 16)
		if _, err := rand.Read(random_session_key); err != nil {
			return nil, nil, fmt.Errorf("failed to generate random session key: %v", err)
		}

		rc4_cipher, err := rc4.NewCipher(session_base_key)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create RC4 cipher for key exchange: %v", err)
		}

		encrypted_random_session_key = make([]byte, 16)
		rc4_cipher.XORKeyStream(encrypted_random_session_key, random_session_key)

		exported_session_key = random_session_key
	} else {
		encrypted_random_session_key = []byte{}
		exported_session_key = session_base_key
	}

	// Build the AUTHENTICATE_MESSAGE.
	// Strip NTLMSSP_NEGOTIATE_VERSION from the flags: this field is for debugging only
	// (per MS-NLMP) and its absence in the authenticate message avoids a nil Version panic.
	auth_msg := &ntlm_authenticate.AuthenticateMessage{}
	auth_msg.NegotiateFlags = challenge_msg.NegotiateFlags &^ ntlm_flags.NTLMSSP_NEGOTIATE_VERSION

	auth_msg.LmChallengeResponse = lm_challenge_response
	auth_msg.NtChallengeResponse = nt_challenge_response
	auth_msg.EncryptedRandomSessionKey = encrypted_random_session_key

	if (challenge_msg.NegotiateFlags & ntlm_flags.NTLMSSP_NEGOTIATE_UNICODE) != 0 {
		auth_msg.DomainName = utf16.EncodeUTF16LE(strings.ToUpper(domain))
		auth_msg.UserName = utf16.EncodeUTF16LE(username)
		auth_msg.Workstation = []byte{}
	} else {
		auth_msg.DomainName = []byte(strings.ToUpper(domain))
		auth_msg.UserName = []byte(username)
		auth_msg.Workstation = []byte{}
	}

	// Marshal with MIC field all zeros.
	auth_bytes, err := auth_msg.Marshal()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal NTLMv2 authenticate message: %v", err)
	}

	if needs_mic {
		// MIC = HMAC-MD5(ExportedSessionKey, Negotiate || Challenge || Authenticate_with_zero_MIC)
		mic_mac := hmac.New(md5.New, exported_session_key)
		mic_mac.Write(negotiate_bytes)
		mic_mac.Write(challenge_bytes)
		mic_mac.Write(auth_bytes)
		mic := mic_mac.Sum(nil)

		// Patch MIC into the authenticate message at byte offset ntlmMicOffset (72).
		copy(auth_bytes[ntlmMicOffset:ntlmMicOffset+16], mic)
	}

	return auth_bytes, exported_session_key, nil
}

// ntlmTargetInfoGetAvValue returns the value bytes for the first AVPair with the given AvId,
// or nil if not found.
//
// Parameters:
//   - target_info ([]byte): The raw TargetInfo bytes from the NTLM CHALLENGE_MESSAGE.
//   - av_id (uint16): The AvId to look up.
//
// Returns:
//   - []byte: The value bytes, or nil if the AvId is not present.
func ntlmTargetInfoGetAvValue(target_info []byte, av_id uint16) []byte {
	i := 0
	for i+4 <= len(target_info) {
		current_id := uint16(target_info[i]) | uint16(target_info[i+1])<<8
		av_len := uint16(target_info[i+2]) | uint16(target_info[i+3])<<8
		if current_id == av_id {
			if i+4+int(av_len) > len(target_info) {
				return nil
			}
			return target_info[i+4 : i+4+int(av_len)]
		}
		if current_id == 0x0000 {
			break
		}
		i += 4 + int(av_len)
	}
	return nil
}

// ntlmBuildBlobTargetInfo constructs the TargetInfo to embed in the NTLMv2 blob.
//
// It copies all AVPairs from the challenge TargetInfo, then inserts before the EOL:
//   - MsvAvFlags (AvId=0x0006) = 0x00000002 when needs_mic is true, else 0x00000000.
//
// Parameters:
//   - target_info ([]byte): The TargetInfo bytes from the NTLM CHALLENGE_MESSAGE.
//   - needs_mic (bool): Whether to set the MIC-present bit in MsvAvFlags.
//
// Returns:
//   - []byte: The new TargetInfo for the blob.
func ntlmBuildBlobTargetInfo(target_info []byte, needs_mic bool) []byte {
	result := make([]byte, 0, len(target_info)+8)

	i := 0
	for i+4 <= len(target_info) {
		current_id := uint16(target_info[i]) | uint16(target_info[i+1])<<8
		av_len := uint16(target_info[i+2]) | uint16(target_info[i+3])<<8

		if current_id == 0x0000 {
			// Insert MsvAvFlags before EOL.
			av_flags := uint32(0)
			if needs_mic {
				av_flags = 0x00000002
			}
			result = append(result, 0x06, 0x00, 0x04, 0x00)
			flag_bytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(flag_bytes, av_flags)
			result = append(result, flag_bytes...)
			result = append(result, target_info[i:i+4]...)
			break
		}

		if current_id == 0x0006 {
			// Replace existing MsvAvFlags with our value.
			av_flags := uint32(0)
			if needs_mic {
				av_flags = 0x00000002
			}
			result = append(result, 0x06, 0x00, 0x04, 0x00)
			flag_bytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(flag_bytes, av_flags)
			result = append(result, flag_bytes...)
		} else {
			result = append(result, target_info[i:i+4+int(av_len)]...)
		}

		i += 4 + int(av_len)
	}

	return result
}

// ntlmTargetInfoHasAvId reports whether a TargetInfo AVPair list contains the given AvId.
//
// Parameters:
//   - target_info ([]byte): The raw TargetInfo bytes from the NTLM CHALLENGE_MESSAGE.
//   - av_id (uint16): The AvId to search for (e.g. 0x0007 = MsvAvTimestamp).
//
// Returns:
//   - bool: True if the AvId is present, false otherwise.
func ntlmTargetInfoHasAvId(target_info []byte, av_id uint16) bool {
	i := 0
	for i+4 <= len(target_info) {
		current_id := uint16(target_info[i]) | uint16(target_info[i+1])<<8
		av_len := uint16(target_info[i+2]) | uint16(target_info[i+3])<<8
		if current_id == av_id {
			return true
		}
		if current_id == 0x0000 {
			break
		}
		i += 4 + int(av_len)
	}
	return false
}
