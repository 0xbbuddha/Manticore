package spnego_test

import (
	"encoding/hex"
	"testing"

	"github.com/TheManticoreProject/Manticore/network/smb/smb_v10/spnego"
)

func TestUnmarshalSecurityBlob(t *testing.T) {
	// Test data from a real SPNEGO NegTokenResp message
	blobData, err := hex.DecodeString("a181e83081e5a0030a0101a10c060a2b06010401823702020aa281cf0481cc4e544c4d5353500002000000180018003800000005828aa2cfa9315d6d0bc75200000000000000007c007c00500000000501280a0000000f5400480049004e004b005000410044002d00580036003100020018005400480049004e004b005000410044002d00580036003100010018005400480049004e004b005000410044002d00580036003100040018007400680069006e006b007000610064002d00780036003100030018007400680069006e006b007000610064002d00780036003100060004000100000000000000")
	if err != nil {
		t.Fatalf("Failed to decode test data: %v", err)
	}

	var blob spnego.SecurityBlob
	_, err = blob.Unmarshal(blobData)
	if err != nil {
		t.Fatalf("Failed to unmarshal SecurityBlob: %v", err)
	}
}

func TestMarshalUnmarshalSecurityBlob(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{
			name: "Empty blob",
			data: []byte{},
		},
		{
			name: "Simple data",
			data: []byte{0x01},
		},
		{
			name: "Simple data",
			data: []byte{0x01, 0x02},
		},
		{
			name: "Simple data",
			data: []byte{0x01, 0x02, 0x03},
		},
		{
			name: "Simple data",
			data: []byte{0x01, 0x02, 0x03, 0x04},
		},
		{
			name: "Simple data",
			data: []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		},
		{
			name: "Simple data",
			data: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
		},
		{
			name: "Simple data",
			data: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
		},
		{
			name: "Simple data",
			data: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		},
		{
			name: "NTLM token",
			data: []byte("NTLMSSP\x00\x01\x00\x00\x00"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create and marshal blob
			original := &spnego.SecurityBlob{
				Data: tc.data,
			}

			marshaled, err := original.Marshal()
			if err != nil {
				t.Fatalf("Failed to marshal SecurityBlob: %v", err)
			}

			// Unmarshal and verify
			var unmarshaled spnego.SecurityBlob
			_, err = unmarshaled.Unmarshal(marshaled)
			if err != nil {
				t.Fatalf("Failed to unmarshal SecurityBlob: %v", err)
			}

			// Compare original and unmarshaled data
			if string(unmarshaled.Data) != string(original.Data) {
				t.Errorf("Data mismatch after marshal/unmarshal.\nGot:  %v\nWant: %v",
					unmarshaled.Data, original.Data)
			}
		})
	}
}
