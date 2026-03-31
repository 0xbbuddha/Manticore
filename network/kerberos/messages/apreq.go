package messages

import (
	"encoding/asn1"
	"fmt"
)

// apReqInner is the inner SEQUENCE of an AP-REQ message.
type apReqInner struct {
	// PVNO is the Kerberos protocol version (always 5).
	PVNO int `asn1:"explicit,tag:0"`
	// MsgType is the message type (always MsgTypeAPReq = 14).
	MsgType int `asn1:"explicit,tag:1"`
	// APOptions contains bit flags for the AP request.
	APOptions asn1.BitString `asn1:"explicit,tag:2"`
	// Ticket is the service ticket (APPLICATION[1]), stored as raw bytes.
	Ticket asn1.RawValue `asn1:"explicit,tag:3"`
	// Authenticator is the encrypted authenticator.
	Authenticator EncryptedData `asn1:"explicit,tag:4"`
}

// APReq is a Kerberos AP-REQ (Application Request) message,
// APPLICATION[14], as defined in RFC 4120 Section 5.5.1.
// It is sent by the client to a service as part of mutual authentication,
// and is also embedded in TGS-REQ PA-DATA (PA-TGS-REQ).
type APReq struct {
	// PVNO is the Kerberos protocol version (always 5).
	PVNO int
	// MsgType is the message type (always MsgTypeAPReq = 14).
	MsgType int
	// APOptions contains bit flags controlling the AP exchange.
	APOptions asn1.BitString
	// Ticket is the service ticket obtained from the TGS.
	Ticket Ticket
	// Authenticator is the encrypted Authenticator proving the client's identity.
	Authenticator EncryptedData
}

// Marshal encodes the AP-REQ as an ASN.1 APPLICATION[14] wrapped SEQUENCE.
func (r *APReq) Marshal() ([]byte, error) {
	tkt_bytes, err := r.Ticket.Marshal()
	if err != nil {
		return nil, err
	}
	var tkt_raw asn1.RawValue
	if _, err := asn1.Unmarshal(tkt_bytes, &tkt_raw); err != nil {
		return nil, err
	}

	inner := apReqInner{
		PVNO:          KerberosV5,
		MsgType:       MsgTypeAPReq,
		APOptions:     r.APOptions,
		Ticket:        tkt_raw,
		Authenticator: r.Authenticator,
	}
	seq_contents, err := marshalSequenceContents(inner)
	if err != nil {
		return nil, err
	}
	return wrapApplication(MsgTypeAPReq, seq_contents)
}

// Unmarshal decodes an AP-REQ from an ASN.1 APPLICATION[14] wrapped SEQUENCE.
// Returns the number of bytes consumed from data.
func (r *APReq) Unmarshal(data []byte) (int, error) {
	inner_bytes, consumed, err := unwrapApplication(data, MsgTypeAPReq)
	if err != nil {
		return 0, fmt.Errorf("apreq: %w", err)
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

	var inner apReqInner
	if _, err := asn1.Unmarshal(seq_bytes, &inner); err != nil {
		return 0, fmt.Errorf("apreq inner unmarshal: %w", err)
	}

	r.PVNO = inner.PVNO
	r.MsgType = inner.MsgType
	r.APOptions = inner.APOptions
	r.Authenticator = inner.Authenticator

	// Unmarshal the ticket from the raw value
	tkt_raw_bytes, err := asn1.Marshal(inner.Ticket)
	if err != nil {
		return 0, err
	}
	if _, err := r.Ticket.Unmarshal(tkt_raw_bytes); err != nil {
		return 0, fmt.Errorf("apreq ticket unmarshal: %w", err)
	}

	return consumed, nil
}
