package spnego

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"fmt"
)

// OIDs for various authentication mechanisms
var (
	// SPNEGO OID: 1.3.6.1.5.5.2
	SpnegoOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}

	// NTLM OID: 1.3.6.1.4.1.311.2.2.10
	NtlmOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}

	// Kerberos OID: 1.2.840.113554.1.2.2
	KerberosOID = asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}
)

// NegTokenInit is the initial SPNEGO token sent by the client
// wrapped in a [0] EXPLICIT context tag.
type NegTokenInit struct {
	MechTypes    []asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
	ReqFlags     asn1.BitString          `asn1:"explicit,optional,tag:1"`
	MechToken    []byte                  `asn1:"explicit,optional,tag:2"`
	MechTokenMIC []byte                  `asn1:"explicit,optional,tag:3"`
}

// NegTokenResp is the response token sent by the server
// wrapped in a [0] EXPLICIT context tag.
type NegTokenResp struct {
	NegState      asn1.Enumerated       `asn1:"explicit,optional,tag:0"`
	SupportedMech asn1.ObjectIdentifier `asn1:"explicit,optional,tag:1"`
	ResponseToken []byte                `asn1:"explicit,optional,tag:2"`
	MechListMIC   []byte                `asn1:"explicit,optional,tag:3"`
}

// GSS API constants
const (
	GSS_API_SPNEGO = 0x60 // [APPLICATION 0]
)

// wrapSPNEGO wraps an already-DER-marshaled NegToken... bytes with the SPNEGO OID and [0] tag.
func wrapSPNEGO(innerBytes []byte) ([]byte, error) {
	// Marshal the SPNEGO OID
	oidBytes, err := asn1.Marshal(SpnegoOID)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SPNEGO OID: %v", err)
	}
	// Wrap inner in [0] EXPLICIT
	raw := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      innerBytes,
	}
	wrappedInner, err := asn1.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to wrap inner token: %v", err)
	}

	// Build final buffer: GSS tag, length, OID, wrappedInner
	buf := &bytes.Buffer{}
	buf.WriteByte(GSS_API_SPNEGO)

	totalLen := len(oidBytes) + len(wrappedInner)
	writeLength(buf, totalLen)

	buf.Write(oidBytes)
	buf.Write(wrappedInner)

	return buf.Bytes(), nil
}

// writeLength writes DER length octets for the given length
func writeLength(buf *bytes.Buffer, length int) {
	if length < 128 {
		buf.WriteByte(byte(length))
		return
	}
	// long form
	// determine number of bytes
	var lenBytes []byte
	tmp := length
	for tmp > 0 {
		lenBytes = append([]byte{byte(tmp & 0xFF)}, lenBytes...)
		tmp >>= 8
	}
	buf.WriteByte(0x80 | byte(len(lenBytes)))
	buf.Write(lenBytes)
}

// CreateNegTokenInit creates an ASN.1 encoded SPNEGO NegTokenInit
func CreateNegTokenInit(ntlmToken []byte) ([]byte, error) {
	// Inner NegTokenInit sequence
	token := NegTokenInit{
		MechTypes: []asn1.ObjectIdentifier{NtlmOID},
		MechToken: ntlmToken,
	}

	tknBytes, err := asn1.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal NegTokenInit: %v", err)
	}
	// Wrap and return
	return wrapSPNEGO(tknBytes)
}

// CreateNegTokenResp creates an ASN.1 encoded SPNEGO NegTokenResp
func CreateNegTokenResp(state asn1.Enumerated, mech asn1.ObjectIdentifier, token []byte) ([]byte, error) {
	resp := NegTokenResp{
		NegState:      state,
		SupportedMech: mech,
		ResponseToken: token,
	}

	respBytes, err := asn1.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal NegTokenResp: %v", err)
	}
	return wrapSPNEGO(respBytes)
}

// ParseNegTokenResp parses a server's NegTokenResp and returns the struct
// This function is used to parse the server's NegTokenResp and extract the NTLM token
// It is used to parse the server's NegTokenResp and extract the NTLM token
func ParseNegTokenResp(data []byte) (*NegTokenResp, error) {
	naked, err := stripGSSHeader(data)
	if err != nil {
		return nil, err
	}

	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(naked, &oid)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal OID: %v", err)
	}
	if !oid.Equal(SpnegoOID) {
		return nil, fmt.Errorf("unexpected SPNEGO OID: %v", oid)
	}

	var raw asn1.RawValue
	rest, err = asn1.Unmarshal(rest, &raw)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal context tag: %v", err)
	}
	if raw.Class != asn1.ClassContextSpecific || raw.Tag != 0 || !raw.IsCompound {
		return nil, errors.New("invalid SPNEGO context tag")
	}

	var inner asn1.RawValue
	_, err = asn1.Unmarshal(raw.Bytes, &inner)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal inner SEQUENCE: %v", err)
	}

	var resp NegTokenResp
	_, err = asn1.Unmarshal(inner.FullBytes, &resp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal NegTokenResp: %v", err)
	}

	return &resp, nil
}

// ExtractNTLMToken extracts the NTLM token from a SPNEGO token (init or resp)
func ExtractNTLMToken(spnegoToken []byte) ([]byte, error) {
	// Strip GSS header
	naked, err := stripGSSHeader(spnegoToken)
	if err != nil {
		return nil, err
	}
	// Unmarshal OID
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(naked, &oid)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal OID: %v", err)
	}
	if !oid.Equal(SpnegoOID) {
		return nil, fmt.Errorf("unexpected SPNEGO OID: %v", oid)
	}
	// Strip [0]
	var raw asn1.RawValue
	_, err = asn1.Unmarshal(rest, &raw)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal context tag: %v", err)
	}
	if raw.Class != asn1.ClassContextSpecific || raw.Tag != 0 {
		return nil, errors.New("missing SPNEGO inner context tag")
	}
	// Try NegTokenInit
	var init NegTokenInit
	if _, err := asn1.Unmarshal(raw.Bytes, &init); err == nil && len(init.MechToken) > 0 {
		return init.MechToken, nil
	}
	// Try NegTokenResp
	var resp NegTokenResp
	if _, err := asn1.Unmarshal(raw.Bytes, &resp); err == nil && len(resp.ResponseToken) > 0 {
		return resp.ResponseToken, nil
	}
	return nil, errors.New("no NTLM token found in SPNEGO message")
}

// stripGSSHeader removes the [APPLICATION 0] tag and returns the inner content
func stripGSSHeader(data []byte) ([]byte, error) {
	if len(data) < 2 || data[0] != GSS_API_SPNEGO {
		return nil, errors.New("invalid GSS-API header")
	}
	// parse length
	length, lenLen, err := parseLength(data[1:])
	if err != nil {
		return nil, err
	}
	if 1+lenLen+length > len(data) {
		return nil, errors.New("invalid length in GSS header")
	}
	return data[1+lenLen : 1+lenLen+length], nil
}

// parseLength reads DER length from the start of b, returns (length, totalBytesConsumed, error)
func parseLength(b []byte) (int, int, error) {
	if len(b) < 1 {
		return 0, 0, errors.New("length bytes missing")
	}
	if b[0]&0x80 == 0 {
		// short form
		return int(b[0]), 1, nil
	}
	// long form
	n := int(b[0] & 0x7F)
	if n == 0 || n > len(b)-1 {
		return 0, 0, errors.New("invalid long-form length")
	}
	length := 0
	for i := 0; i < n; i++ {
		length = (length << 8) | int(b[1+i])
	}
	return length, 1 + n, nil
}
