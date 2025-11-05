package blob_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/blob"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/magic"
)

func TestBCRYPT_RSAKEY_BLOB_Unmarshal_Marshal(t *testing.T) {
	tests := []struct {
		name            string
		input           blob.BCRYPT_RSAKEY_BLOB
		wantError       bool
		wantErrorString string
	}{
		{
			name: "Valid RSA key material",
			input: blob.BCRYPT_RSAKEY_BLOB{
				Magic:       magic.BCRYPT_RSAPUBLIC_MAGIC,
				BitLength:   2048,
				CbPublicExp: 65535,
				CbModulus:   256,
				CbPrime1:    0,
				CbPrime2:    0,
			},
			wantError:       false,
			wantErrorString: "",
		},

		{
			name: "Valid RSA private key material",
			input: blob.BCRYPT_RSAKEY_BLOB{
				Magic:       magic.BCRYPT_RSAPRIVATE_MAGIC,
				BitLength:   2048,
				CbPublicExp: 65535,
				CbModulus:   256,
				CbPrime1:    128,
				CbPrime2:    128,
			},
			wantError:       false,
			wantErrorString: "",
		},

		{
			name: "Valid RSA full private key material",
			input: blob.BCRYPT_RSAKEY_BLOB{
				Magic:       magic.BCRYPT_RSAFULLPRIVATE_MAGIC,
				BitLength:   2048,
				CbPublicExp: 65535,
				CbModulus:   256,
				CbPrime1:    128,
				CbPrime2:    128,
			},
			wantError:       false,
			wantErrorString: "",
		},

		{
			name: "Invalid RSA public key material - prime1 size is not 0",
			input: blob.BCRYPT_RSAKEY_BLOB{
				Magic:       magic.BCRYPT_RSAPUBLIC_MAGIC,
				BitLength:   2048,
				CbPublicExp: 65535,
				CbModulus:   256,
				CbPrime1:    128,
				CbPrime2:    0,
			},
			wantError:       true,
			wantErrorString: "prime1 size is not 0, public key cannot have prime1",
		},

		{
			name: "Invalid RSA public key material - prime2 size is not 0",
			input: blob.BCRYPT_RSAKEY_BLOB{
				Magic:       magic.BCRYPT_RSAPUBLIC_MAGIC,
				BitLength:   2048,
				CbPublicExp: 65535,
				CbModulus:   256,
				CbPrime1:    0,
				CbPrime2:    128,
			},
			wantError:       true,
			wantErrorString: "prime2 size is not 0, public key cannot have prime2",
		},

		{
			name: "Invalid RSA private key material - prime1 size is 0",
			input: blob.BCRYPT_RSAKEY_BLOB{
				Magic:       magic.BCRYPT_RSAPRIVATE_MAGIC,
				BitLength:   2048,
				CbPublicExp: 65535,
				CbModulus:   256,
				CbPrime1:    0,
				CbPrime2:    128,
			},
			wantError:       true,
			wantErrorString: "prime1 size is 0, private key needs to have prime1",
		},

		{
			name: "Invalid RSA private key material - prime2 size is 0",
			input: blob.BCRYPT_RSAKEY_BLOB{
				Magic:       magic.BCRYPT_RSAPRIVATE_MAGIC,
				BitLength:   2048,
				CbPublicExp: 65535,
				CbModulus:   256,
				CbPrime1:    128,
				CbPrime2:    0,
			},
			wantError:       true,
			wantErrorString: "prime2 size is 0, private key needs to have prime2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rk := &blob.BCRYPT_RSAKEY_BLOB{}
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
