package blob_test

import (
	"bytes"
	"testing"

	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/blob"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/headers"
)

func TestBCRYPT_DSA_PRIVATE_BLOB_MarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name            string
		header          headers.BCRYPT_DSA_KEY_BLOB
		input           blob.BCRYPT_DSA_PRIVATE_BLOB
		wantError       bool
		wantErrorString string
	}{
		{
			name: "Valid DSA private key material",
			header: headers.BCRYPT_DSA_KEY_BLOB{
				CbKey: 2048,
				Count: [4]byte{0x11, 0x22, 0x33, 0x44},
				Seed:  [20]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
				Q:     [20]byte{19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
			},
			input: blob.BCRYPT_DSA_PRIVATE_BLOB{
				Modulus:   make([]byte, 2048),
				Generator: make([]byte, 2048),
				Public:    make([]byte, 2048),
			},
			wantError:       false,
			wantErrorString: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := tt.input.Marshal()
			if err != nil {
				t.Errorf("Marshal() error = %v", err)
				return
			}

			rk := &blob.BCRYPT_DSA_PRIVATE_BLOB{}
			_, err = rk.Unmarshal(tt.header, data)
			if err != nil {
				t.Errorf("Marshal() error = %v", err)
				return
			}
			if err != nil {
				t.Errorf("Unmarshal() error = %v", err)
				return
			}
			if !bytes.Equal(rk.Modulus, tt.input.Modulus) {
				t.Errorf("Modulus mismatch after unmarshal")
			}
			if !bytes.Equal(rk.Generator, tt.input.Generator) {
				t.Errorf("Generator mismatch after unmarshal")
			}
			if !bytes.Equal(rk.Public, tt.input.Public) {
				t.Errorf("Public mismatch after unmarshal")
			}
		})
	}
}
