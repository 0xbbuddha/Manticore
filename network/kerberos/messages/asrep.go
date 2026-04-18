package messages

import (
	"encoding/asn1"
	"fmt"
)

// kdcRepInner is the inner SEQUENCE of a KDC reply (AS-REP or TGS-REP).
type kdcRepInner struct {
	// PVNO is the Kerberos protocol version (always 5).
	PVNO int `asn1:"explicit,tag:0"`
	// MsgType is the message type (MsgTypeASRep = 11 or MsgTypeTGSRep = 13).
	MsgType int `asn1:"explicit,tag:1"`
	// PAData contains optional pre-authentication data.
	PAData []PAData `asn1:"explicit,tag:2,optional"`
	// CRealm is the client's realm.
	CRealm string `asn1:"explicit,tag:3,generalstring"`
	// CName is the client's principal name.
	CName PrincipalName `asn1:"explicit,tag:4"`
	// Ticket is the issued ticket (APPLICATION[1]), stored as raw bytes.
	Ticket asn1.RawValue `asn1:"explicit,tag:5"`
	// EncPart is the encrypted part of the reply containing the session key.
	EncPart EncryptedData `asn1:"explicit,tag:6"`
}

// ASRep is a Kerberos AS-REP (Authentication Service Reply) message,
// APPLICATION[11], as defined in RFC 4120 Section 5.4.2.
// It is sent by the KDC in response to a successful AS-REQ.
type ASRep struct {
	// PVNO is the Kerberos protocol version (always 5).
	PVNO int
	// MsgType is the message type (always MsgTypeASRep = 11).
	MsgType int
	// PAData contains pre-authentication data (rarely set in AS-REP).
	PAData []PAData
	// CRealm is the realm of the client.
	CRealm string
	// CName is the client's principal name as returned by the KDC.
	CName PrincipalName
	// Ticket is the issued Ticket Granting Ticket.
	Ticket Ticket
	// EncPart is the encrypted reply body, decryptable with the client's key.
	EncPart EncryptedData
}

// Marshal encodes the AS-REP as an ASN.1 APPLICATION[11] wrapped SEQUENCE.
func (r *ASRep) Marshal() ([]byte, error) {
	tkt_bytes, err := r.Ticket.Marshal()
	if err != nil {
		return nil, err
	}
	var tkt_raw asn1.RawValue
	if _, err := asn1.Unmarshal(tkt_bytes, &tkt_raw); err != nil {
		return nil, err
	}

	inner := kdcRepInner{
		PVNO:    KerberosV5,
		MsgType: MsgTypeASRep,
		PAData:  r.PAData,
		CRealm:  r.CRealm,
		CName:   r.CName,
		Ticket:  tkt_raw,
		EncPart: r.EncPart,
	}
	seq_contents, err := marshalSequenceContents(inner)
	if err != nil {
		return nil, err
	}
	return wrapApplication(MsgTypeASRep, seq_contents)
}

// Unmarshal decodes an AS-REP from an ASN.1 APPLICATION[11] wrapped SEQUENCE.
// Returns the number of bytes consumed from data.
func (r *ASRep) Unmarshal(data []byte) (int, error) {
	inner_bytes, consumed, err := unwrapApplication(data, MsgTypeASRep)
	if err != nil {
		return 0, fmt.Errorf("asrep: %w", err)
	}

	seq_bytes, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      inner_bytes,
	})
	if err != nil {
		return 0, err
	}

	var inner kdcRepInner
	if _, err := asn1.Unmarshal(seq_bytes, &inner); err != nil {
		return 0, fmt.Errorf("asrep inner unmarshal: %w", err)
	}

	r.PVNO = inner.PVNO
	r.MsgType = inner.MsgType
	r.PAData = inner.PAData
	r.CRealm = inner.CRealm
	r.CName = inner.CName
	r.EncPart = inner.EncPart

	// Unmarshal the ticket from the raw value
	tkt_raw_bytes, err := asn1.Marshal(inner.Ticket)
	if err != nil {
		return 0, err
	}
	if _, err := r.Ticket.Unmarshal(tkt_raw_bytes); err != nil {
		return 0, fmt.Errorf("asrep ticket unmarshal: %w", err)
	}

	return consumed, nil
}
