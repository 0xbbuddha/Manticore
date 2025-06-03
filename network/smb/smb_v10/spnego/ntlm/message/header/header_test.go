package header_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/network/smb/smb_v10/spnego/ntlm/message/header"
	"github.com/TheManticoreProject/Manticore/network/smb/smb_v10/spnego/ntlm/message/types"
)

func TestHeaderMarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name      string
		signature [8]byte
		msgType   types.MessageType
		wantError bool
	}{
		{
			name:      "Standard NTLM Header",
			signature: header.NTLM_SIGNATURE,
			msgType:   types.NEGOTIATE_MESSAGE_TYPE,
			wantError: false,
		},
		{
			name:      "Custom Signature",
			signature: [8]byte{'T', 'E', 'S', 'T', 'S', 'I', 'G', 0},
			msgType:   types.CHALLENGE_MESSAGE_TYPE,
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create original header
			original := &header.Header{
				Signature:   tt.signature,
				MessageType: tt.msgType,
			}

			// Marshal
			data, err := original.Marshal()
			if (err != nil) != tt.wantError {
				t.Errorf("Marshal() error = %v, wantError %v", err, tt.wantError)
				return
			}

			if tt.wantError {
				return
			}

			// Unmarshal into new header
			unmarshalled := &header.Header{}
			_, err = unmarshalled.Unmarshal(data)
			if err != nil {
				t.Errorf("Unmarshal() error = %v", err)
				return
			}

			// Compare values
			if original.GetSignature() != unmarshalled.GetSignature() {
				t.Errorf("Signature mismatch after marshal/unmarshal: got %v, want %v",
					unmarshalled.GetSignature(), original.GetSignature())
			}

			if original.GetType() != unmarshalled.GetType() {
				t.Errorf("MessageType mismatch after marshal/unmarshal: got %v, want %v",
					unmarshalled.GetType(), original.GetType())
			}
		})
	}
}
