package spnego

import (
	"encoding/asn1"
	"fmt"
)

// SecurityBlob represents a security token wrapped in ASN.1 encoding.
// It contains arbitrary security token data that is tagged with ASN.1 metadata.
type SecurityBlob struct {
	Data []byte `asn1:"explicit,tag:0,octet"`
}

// Unmarshal decodes an ASN.1 encoded security blob into this SecurityBlob struct.
// The data is expected to be wrapped in a [1] ASN.1 tag.
//
// Parameters:
//   - marshalledData: The ASN.1 encoded bytes to unmarshal
//
// Returns:
//   - int: Number of bytes read from marshalledData
//   - error: Any error encountered during unmarshaling
func (s *SecurityBlob) Unmarshal(marshalledData []byte) (int, error) {
	// This is wrapped in a [1] tag, so we first extract the inner SEQUENCE
	var outerRaw asn1.RawValue
	rest, err := asn1.Unmarshal(marshalledData, &outerRaw)
	if err != nil {
		return 0, fmt.Errorf("outer Unmarshal error: %v", err)
	}
	bytesRead := len(marshalledData) - len(rest)

	if outerRaw.Class != 2 || outerRaw.Tag != 1 {
		return 0, fmt.Errorf("unexpected outer tag: class=%d tag=%d", outerRaw.Class, outerRaw.Tag)
	}

	s.Data = outerRaw.Bytes

	return bytesRead, nil
}

// Marshal encodes this SecurityBlob into ASN.1 format.
// The data is wrapped in a [1] ASN.1 tag before encoding.
//
// Returns:
//   - []byte: The ASN.1 encoded security blob
//   - error: Any error encountered during marshaling
func (s *SecurityBlob) Marshal() ([]byte, error) {
	// Create ASN.1 RawValue with [1] tag wrapping the data
	raw := asn1.RawValue{
		Class:      2, // Context-specific
		Tag:        1,
		IsCompound: true,
		Bytes:      s.Data,
	}

	// Marshal the RawValue
	data, err := asn1.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SecurityBlob: %v", err)
	}

	return data, nil
}
