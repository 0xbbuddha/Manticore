package messages

import (
	"encoding/asn1"
)

// ticketInner is the inner SEQUENCE of a Kerberos Ticket, as defined in RFC 4120 Section 5.3.
type ticketInner struct {
	// TktVno is the ticket version number (always 5).
	TktVno int `asn1:"explicit,tag:0"`
	// Realm is the realm of the principal named in the SName field.
	Realm string `asn1:"explicit,tag:1,generalstring"`
	// SName is the name of the server for which the ticket was issued.
	SName PrincipalName `asn1:"explicit,tag:2"`
	// EncPart is the encrypted part of the ticket.
	EncPart EncryptedData `asn1:"explicit,tag:3"`
}

// Ticket is a Kerberos ticket (APPLICATION[1]), as defined in RFC 4120 Section 5.3.
// It carries an encrypted session key and authorization data for a service principal.
type Ticket struct {
	// TktVno is the Kerberos version number embedded in the ticket (always 5).
	TktVno int
	// Realm is the realm of the service principal.
	Realm string
	// SName is the name of the service principal.
	SName PrincipalName
	// EncPart is the encrypted portion of the ticket.
	EncPart EncryptedData
}

// Marshal encodes the Ticket as an ASN.1 APPLICATION[1] wrapped SEQUENCE.
func (t *Ticket) Marshal() ([]byte, error) {
	inner := ticketInner{
		TktVno:  t.TktVno,
		Realm:   t.Realm,
		SName:   t.SName,
		EncPart: t.EncPart,
	}
	seq_contents, err := marshalSequenceContents(inner)
	if err != nil {
		return nil, err
	}
	return wrapApplication(1, seq_contents)
}

// Unmarshal decodes a Ticket from an ASN.1 APPLICATION[1] wrapped SEQUENCE.
// Returns the number of bytes consumed from data.
func (t *Ticket) Unmarshal(data []byte) (int, error) {
	inner_bytes, consumed, err := unwrapApplication(data, 1)
	if err != nil {
		return 0, err
	}

	// inner_bytes is the raw SEQUENCE contents (no tag/len wrapper)
	// We need to wrap it back in a SEQUENCE for asn1.Unmarshal
	seq_bytes, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagSequence,
		IsCompound: true,
		Bytes:      inner_bytes,
	})
	if err != nil {
		return 0, err
	}

	var inner ticketInner
	if _, err := asn1.Unmarshal(seq_bytes, &inner); err != nil {
		return 0, err
	}

	t.TktVno = inner.TktVno
	t.Realm = inner.Realm
	t.SName = inner.SName
	t.EncPart = inner.EncPart
	return consumed, nil
}
