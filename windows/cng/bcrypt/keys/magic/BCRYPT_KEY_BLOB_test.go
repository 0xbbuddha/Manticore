package magic_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/magic"
)

func TestBCRYPT_KEY_BLOB_UnmarshalMarshal(t *testing.T) {
	tests := []struct {
		name  string
		input magic.BCRYPT_KEY_BLOB
	}{
		{
			name: "Valid RSA public key material",
			input: magic.BCRYPT_KEY_BLOB{
				Magic: magic.BCRYPT_RSAPUBLIC_MAGIC,
			},
		},
		{
			name: "Valid RSA private key material",
			input: magic.BCRYPT_KEY_BLOB{
				Magic: magic.BCRYPT_RSAPRIVATE_MAGIC,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			marshalledData, err := tt.input.Marshal()
			if err != nil {
				t.Errorf("Marshal() error = %v", err)
			}

			blob2 := magic.BCRYPT_KEY_BLOB{}
			_, err = blob2.Unmarshal(marshalledData)
			if err != nil {
				t.Errorf("Unmarshal() error = %v", err)
			}

			if !blob2.Equal(&tt.input) {
				t.Errorf("Marshal() = %v, want %v", blob2, tt.input)
			}
		})
	}
}
