package spnego

import (
	"encoding/asn1"
	"fmt"
)

// NegState represents the negotiation state in SPNEGO
type NegState asn1.Enumerated

const (
	// NegStateAcceptCompleted indicates the negotiation is complete and successful
	NegStateAcceptCompleted NegState = 0
	// NegStateAcceptIncomplete indicates more negotiation messages are needed
	NegStateAcceptIncomplete NegState = 1
	// NegStateReject indicates the negotiation has failed
	NegStateReject NegState = 2
	// NegStateRequestMIC indicates a MIC token is requested
	NegStateRequestMIC NegState = 3
)

// String returns a string representation of the NegState
// Parameters:
//   - n: The NegState to convert to a string
//
// Returns:
//   - string: A string representation of the NegState
func (n NegState) String() string {
	switch n {
	case NegStateAcceptCompleted:
		return "Accept Completed (1)"
	case NegStateAcceptIncomplete:
		return "Accept Incomplete (2)"
	case NegStateReject:
		return "Reject (3)"
	case NegStateRequestMIC:
		return "Request MIC (4)"
	default:
		return fmt.Sprintf("%d (?)", n)
	}
}

// NegTokenResp is the response token sent by the server
/*
	NegTokenResp ::= SEQUENCE {
	    negState[0]       ENUMERATED {
	        accept-completed(0),
	        accept-incomplete(1),
	        reject(2),
	        request-mic(3)
	    } OPTIONAL,
	    supportedMech[1]  MechType OPTIONAL,
	    responseToken[2]  OCTET STRING OPTIONAL,
	    mechListMIC[3]    OCTET STRING OPTIONAL
	}
*/
type NegTokenResp struct {
	NegState      NegState              `asn1:"explicit,optional,tag:0"`
	SupportedMech asn1.ObjectIdentifier `asn1:"explicit,optional,tag:1"`
	ResponseToken []byte                `asn1:"explicit,optional,tag:2,octet"`
	MechListMIC   []byte                `asn1:"explicit,optional,tag:3,octet"`
}

// NewNegTokenResp creates a new NegTokenResp
// Parameters:
//   - state: The negotiation state
//   - mech: The supported mechanism OID
//   - responseToken: The response token bytes
//
// Returns:
//   - *NegTokenResp: A new NegTokenResp instance
func NewNegTokenResp(state NegState, mech asn1.ObjectIdentifier, responseToken []byte) *NegTokenResp {
	return &NegTokenResp{
		NegState:      state,
		SupportedMech: mech,
		ResponseToken: responseToken,
	}
}

// SetMechToken sets the mech token in the NegTokenResp
// Parameters:
//   - responseToken: The response token bytes to set
func (n *NegTokenResp) SetMechToken(responseToken []byte) {
	n.ResponseToken = responseToken
}

// SetMechTokenNTLM sets the NTLM token in the NegTokenResp
// Parameters:
//   - responseToken: The NTLM response token bytes to set
func (n *NegTokenResp) SetMechTokenNTLM(responseToken []byte) {
	n.SupportedMech = NtlmOID
	n.ResponseToken = responseToken
}

// Marshal marshals the NegTokenResp into a byte slice
// Returns:
//   - []byte: The marshaled bytes
//   - error: An error if marshaling fails
func (n *NegTokenResp) Marshal() ([]byte, error) {
	marshalledData, err := asn1.Marshal(*n)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal NegTokenResp: %v", err)
	}
	return marshalledData, nil
}

// Unmarshal unmarshals the NegTokenResp from a byte slice
// Parameters:
//   - data: The bytes to unmarshal
//
// Returns:
//   - error: An error if unmarshaling fails
func (n *NegTokenResp) Unmarshal(data []byte) (int, error) {
	rest, err := asn1.Unmarshal(data, n)
	if err != nil {
		return 0, fmt.Errorf("failed to unmarshal NegTokenResp: %v", err)
	}
	bytesRead := len(data) - len(rest)
	return bytesRead, nil
}

// CreateNegTokenResp creates an ASN.1 encoded SPNEGO NegTokenResp
// Parameters:
//   - state: The negotiation state
//   - mech: The supported mechanism OID
//   - token: The response token bytes
//
// Returns:
//   - []byte: The encoded SPNEGO token
//   - error: An error if token creation fails
func CreateNegTokenResp(state NegState, mech asn1.ObjectIdentifier, token []byte) ([]byte, error) {
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
