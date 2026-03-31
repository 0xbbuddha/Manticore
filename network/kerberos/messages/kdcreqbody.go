package messages

import (
	"encoding/asn1"
	"time"
)

// KDCReqBody is the body of a KDC request (AS-REQ or TGS-REQ),
// as defined in RFC 4120 Section 5.4.1.
type KDCReqBody struct {
	// KDCOptions contains bit flags controlling the KDC request behavior.
	KDCOptions asn1.BitString `asn1:"explicit,tag:0"`
	// CName is the client principal name (present in AS-REQ, absent in TGS-REQ).
	CName PrincipalName `asn1:"explicit,tag:1,optional"`
	// Realm is the realm for the request (crealm in AS-REQ, srealm in TGS-REQ).
	Realm string `asn1:"explicit,tag:2,generalstring"`
	// SName is the server principal name being requested.
	SName PrincipalName `asn1:"explicit,tag:3,optional"`
	// From is the requested start time for the ticket (optional).
	From time.Time `asn1:"explicit,tag:4,optional,generalized"`
	// Till is the requested expiry time for the ticket.
	Till time.Time `asn1:"explicit,tag:5,generalized"`
	// RTime is the requested renewable lifetime end time (optional).
	RTime time.Time `asn1:"explicit,tag:6,optional,generalized"`
	// Nonce is a random number used to detect replays.
	Nonce int `asn1:"explicit,tag:7"`
	// EType lists the client's supported encryption types, in preference order.
	EType []int `asn1:"explicit,tag:8"`
	// Addresses restricts the ticket to specific network addresses (optional).
	Addresses []HostAddress `asn1:"explicit,tag:9,optional"`
	// EncAuthData contains encrypted authorization data (optional, TGS-REQ).
	EncAuthData EncryptedData `asn1:"explicit,tag:10,optional"`
	// AdditTickets contains additional tickets (optional, for TGS renewal/forwarding).
	AdditTickets []Ticket `asn1:"explicit,tag:11,optional"`
}
