package messages

import (
	"encoding/asn1"
	"time"
)

// KerberosTime represents a Kerberos timestamp (GeneralizedTime without fractional seconds).
// It is stored as a standard Go time.Time value.
type KerberosTime = time.Time

// PrincipalName contains a name-type and a sequence of name strings,
// as defined in RFC 4120 Section 5.2.2.
type PrincipalName struct {
	// NameType specifies the type of name (e.g. NT-PRINCIPAL = 1).
	NameType int `asn1:"explicit,tag:0"`
	// NameString contains the sequence of name components.
	NameString []string `asn1:"explicit,tag:1"`
}

// EncryptedData holds a Kerberos encrypted blob, as defined in RFC 4120 Section 5.2.9.
// The actual encryption algorithm and key are identified by EType.
type EncryptedData struct {
	// EType identifies the encryption algorithm used.
	EType int `asn1:"explicit,tag:0"`
	// KvNo is the optional key version number.
	KvNo int `asn1:"explicit,tag:1,optional"`
	// Cipher contains the encrypted bytes.
	Cipher []byte `asn1:"explicit,tag:2"`
}

// HostAddress represents a network address, as defined in RFC 4120 Section 5.2.5.
type HostAddress struct {
	// AddrType identifies the address type (e.g. 2 = IPv4, 24 = IPv6).
	AddrType int `asn1:"explicit,tag:0"`
	// Address contains the raw address bytes.
	Address []byte `asn1:"explicit,tag:1"`
}

// AuthorizationData is an authorization-data element, as defined in RFC 4120 Section 5.2.6.
type AuthorizationData struct {
	// ADType identifies the authorization-data type.
	ADType int `asn1:"explicit,tag:0"`
	// ADData contains the type-specific authorization data.
	ADData []byte `asn1:"explicit,tag:1"`
}

// PAData is a pre-authentication data element, as defined in RFC 4120 Section 5.2.7.
type PAData struct {
	// PADataType identifies the pre-authentication data type.
	PADataType int `asn1:"explicit,tag:1"`
	// PADataValue contains the pre-authentication data bytes.
	PADataValue []byte `asn1:"explicit,tag:2"`
}

// KDCOptions is a bit string encoding KDC request options flags,
// as defined in RFC 4120 Section 5.4.1.
type KDCOptions = asn1.BitString

// marshalSequenceContents marshals v to ASN.1 and returns the raw SEQUENCE contents
// (stripping the outer SEQUENCE tag and length).
func marshalSequenceContents(v interface{}) ([]byte, error) {
	b, err := asn1.Marshal(v)
	if err != nil {
		return nil, err
	}
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	return raw.Bytes, nil
}

// wrapApplication wraps the given inner bytes in an ASN.1 APPLICATION tag.
func wrapApplication(tag int, inner []byte) ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassApplication,
		Tag:        tag,
		IsCompound: true,
		Bytes:      inner,
	})
}

// unwrapApplication unwraps an ASN.1 APPLICATION tag from data and verifies the tag.
// Returns the inner bytes and the number of bytes consumed from data.
func unwrapApplication(data []byte, expected_tag int) (inner []byte, consumed int, err error) {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(data, &raw)
	if err != nil {
		return nil, 0, err
	}
	if raw.Class != asn1.ClassApplication || raw.Tag != expected_tag {
		return nil, 0, asn1.StructuralError{Msg: "wrong APPLICATION tag"}
	}
	return raw.Bytes, len(data) - len(rest), nil
}
