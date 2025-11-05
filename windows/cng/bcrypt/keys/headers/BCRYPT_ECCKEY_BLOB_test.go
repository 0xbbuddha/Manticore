package headers_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/headers"
)

func TestBCRYPT_ECCKEY_BLOB_Unmarshal_Marshal(t *testing.T) {
	tests := []struct {
		name            string
		input           headers.BCRYPT_ECCKEY_BLOB
		wantError       bool
		wantErrorString string
	}{
		{
			name: "Valid ECC key material",
			input: headers.BCRYPT_ECCKEY_BLOB{
				KeySize: 256,
			},
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rk := &headers.BCRYPT_ECCKEY_BLOB{}
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
