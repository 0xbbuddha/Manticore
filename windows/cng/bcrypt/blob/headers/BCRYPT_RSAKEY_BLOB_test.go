package headers_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/blob/headers"
)

func TestBCRYPT_RSAKEY_BLOB_Unmarshal_Marshal(t *testing.T) {
	tests := []struct {
		name            string
		input           headers.BCRYPT_RSAKEY_BLOB
		wantError       bool
		wantErrorString string
	}{
		{
			name: "Valid RSA key material",
			input: headers.BCRYPT_RSAKEY_BLOB{
				BitLength:   2048,
				CbPublicExp: 65535,
				CbModulus:   256,
				CbPrime1:    0,
				CbPrime2:    0,
			},
			wantError: false,
		},

		{
			name: "Valid RSA private key material",
			input: headers.BCRYPT_RSAKEY_BLOB{
				BitLength:   2048,
				CbPublicExp: 65535,
				CbModulus:   256,
				CbPrime1:    128,
				CbPrime2:    128,
			},
			wantError: false,
		},

		{
			name: "Valid RSA full private key material",
			input: headers.BCRYPT_RSAKEY_BLOB{
				BitLength:   2048,
				CbPublicExp: 65535,
				CbModulus:   256,
				CbPrime1:    128,
				CbPrime2:    128,
			},
			wantError: false,
		},

		{
			name: "Invalid RSA public key material - prime1 size is not 0",
			input: headers.BCRYPT_RSAKEY_BLOB{
				BitLength:   2048,
				CbPublicExp: 65535,
				CbModulus:   256,
				CbPrime1:    128,
				CbPrime2:    0,
			},
			wantError: false,
		},

		{
			name: "Invalid RSA public key material - prime2 size is not 0",
			input: headers.BCRYPT_RSAKEY_BLOB{
				BitLength:   2048,
				CbPublicExp: 65535,
				CbModulus:   256,
				CbPrime1:    0,
				CbPrime2:    128,
			},
			wantError: false,
		},

		{
			name: "Invalid RSA private key material - prime1 size is 0",
			input: headers.BCRYPT_RSAKEY_BLOB{
				BitLength:   2048,
				CbPublicExp: 65535,
				CbModulus:   256,
				CbPrime1:    0,
				CbPrime2:    128,
			},
			wantError: false,
		},

		{
			name: "Invalid RSA private key material - prime2 size is 0",
			input: headers.BCRYPT_RSAKEY_BLOB{
				BitLength:   2048,
				CbPublicExp: 65535,
				CbModulus:   256,
				CbPrime1:    128,
				CbPrime2:    0,
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rk := &headers.BCRYPT_RSAKEY_BLOB{}
			data, err := tt.input.Marshal()
			if err != nil {
				t.Errorf("Marshal() error = %v", err)
				return
			}
			_, err = rk.Unmarshal(data)
			if (err != nil) != tt.wantError {
				t.Errorf("Unmarshal() error = %v, wantError %v", err, tt.wantError)
			}
			if err != nil && err.Error() != tt.wantErrorString {
				t.Errorf("Unmarshal() error = %v, wantError %v", err, tt.wantErrorString)
			}
		})
	}
}
