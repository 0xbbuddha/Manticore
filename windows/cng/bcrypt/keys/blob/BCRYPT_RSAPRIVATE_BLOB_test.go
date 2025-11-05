package blob_test

import (
	"bytes"
	"testing"

	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/blob"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/headers"
)

func TestBCRYPT_RSAPRIVATE_BLOB_MarshalUnmarshal(t *testing.T) {
	tests := []struct {
		name            string
		header          headers.BCRYPT_RSAKEY_BLOB
		input           blob.BCRYPT_RSAPRIVATE_BLOB
		wantError       bool
		wantErrorString string
	}{
		{
			name: "Valid RSA private key material",
			header: headers.BCRYPT_RSAKEY_BLOB{
				BitLength:   2048,
				CbPublicExp: 3,
				CbModulus:   256,
				CbPrime1:    112,
				CbPrime2:    156,
			},
			input: blob.BCRYPT_RSAPRIVATE_BLOB{
				PublicExponent: []byte{0x01, 0x00, 0x01},
				Modulus:        make([]byte, 256),
				Prime1:         make([]byte, 112),
				Prime2:         make([]byte, 156),
			},
			wantError:       false,
			wantErrorString: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rk := &blob.BCRYPT_RSAPRIVATE_BLOB{}
			data, err := tt.input.Marshal()
			if err != nil {
				t.Errorf("Marshal() error = %v", err)
				return
			}

			_, err = rk.Unmarshal(tt.header, data)
			if (err != nil) != tt.wantError {
				t.Errorf("Unmarshal() error = %v, wantError %v", err, tt.wantError)
			}
			if err != nil && err.Error() != tt.wantErrorString {
				t.Errorf("Unmarshal() error = %v, wantError %v", err, tt.wantErrorString)
			}

			if !bytes.Equal(rk.PublicExponent, tt.input.PublicExponent) {
				t.Errorf("PublicExponent mismatch after unmarshal")
			}
			if !bytes.Equal(rk.Modulus, tt.input.Modulus) {
				t.Errorf("Modulus mismatch after unmarshal")
			}
			if !bytes.Equal(rk.Prime1, tt.input.Prime1) {
				t.Errorf("Prime1 mismatch after unmarshal")
			}
			if !bytes.Equal(rk.Prime2, tt.input.Prime2) {
				t.Errorf("Prime2 mismatch after unmarshal")
			}
		})
	}
}
