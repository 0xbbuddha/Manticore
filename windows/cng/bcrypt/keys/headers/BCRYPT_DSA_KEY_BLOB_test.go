package headers_test

import (
	"bytes"
	"testing"

	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/headers"
)

func TestBCRYPT_DSA_KEY_BLOB_Unmarshal_Marshal(t *testing.T) {
	tests := []struct {
		name            string
		input           headers.BCRYPT_DSA_KEY_BLOB
		wantError       bool
		wantErrorString string
	}{
		{
			name: "Valid DSA key blob",
			input: headers.BCRYPT_DSA_KEY_BLOB{
				CbKey: 2048,
				Count: [4]byte{0x11, 0x22, 0x33, 0x44},
				Seed:  [20]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
				Q:     [20]byte{19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
			},
			wantError: false,
		},
		{
			name:  "Invalid buffer (too short)",
			input: headers.BCRYPT_DSA_KEY_BLOB{
				// Empty fields result in a valid serializable struct, but we will simulate
				// shorter buffer by manually constructing input in the test.
			},
			wantError:       true,
			wantErrorString: "buffer too small for BCRYPT_DSA_KEY_BLOB, 48 bytes required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.wantError && tt.name == "Invalid buffer (too short)" {
				// Try to unmarshal a too-short buffer
				blob := &headers.BCRYPT_DSA_KEY_BLOB{}
				shortBuf := make([]byte, 20)
				_, err := blob.Unmarshal(shortBuf)
				if (err != nil) != tt.wantError {
					t.Errorf("Unmarshal() error = %v, wantError %v", err, tt.wantError)
				}
				if err != nil && err.Error() != tt.wantErrorString {
					t.Errorf("Unmarshal() error = %v, wantErrorString %v", err, tt.wantErrorString)
				}
				return
			}
			// Normal roundtrip
			data, err := tt.input.Marshal()
			if err != nil {
				t.Fatalf("Marshal() error = %v", err)
			}
			var blob headers.BCRYPT_DSA_KEY_BLOB
			n, err := blob.Unmarshal(data)
			if (err != nil) != tt.wantError {
				t.Errorf("Unmarshal() error = %v, wantError %v", err, tt.wantError)
			}
			if err != nil && err.Error() != tt.wantErrorString {
				t.Errorf("Unmarshal() error = %v, wantError %v", err, tt.wantErrorString)
			}
			if n != len(data) && !tt.wantError {
				t.Errorf("Unmarshal() consumed %d bytes, want %d", n, len(data))
			}
			if !tt.wantError {
				// Check that fields roundtrip
				if blob.CbKey != tt.input.CbKey {
					t.Errorf("CbKey = %v, want %v", blob.CbKey, tt.input.CbKey)
				}
				if !bytes.Equal(blob.Count[:], tt.input.Count[:]) {
					t.Errorf("Count = %v, want %v", blob.Count, tt.input.Count)
				}
				if !bytes.Equal(blob.Seed[:], tt.input.Seed[:]) {
					t.Errorf("Seed = %v, want %v", blob.Seed, tt.input.Seed)
				}
				if !bytes.Equal(blob.Q[:], tt.input.Q[:]) {
					t.Errorf("Q = %v, want %v", blob.Q, tt.input.Q)
				}
			}
		})
	}
}
