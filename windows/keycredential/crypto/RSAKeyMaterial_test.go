package crypto

import (
	"testing"
)

func TestRSAKeyMaterial_Unmarshal_Marshal(t *testing.T) {
	tests := []struct {
		name    string
		input   RSAKeyMaterial
		wantErr bool
	}{
		{
			name: "Valid RSA key material",
			input: RSAKeyMaterial{
				KeySize:  8,
				Exponent: 0b10000000000000001,
				Modulus:  []byte{0x11, 0x11, 0x11, 0x11},
				Prime1:   []byte{0x22, 0x22, 0x22, 0x22},
				Prime2:   []byte{0x33, 0x33, 0x33, 0x33},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rk := &RSAKeyMaterial{}
			data, err := tt.input.Marshal()
			if err != nil {
				t.Errorf("Marshal() error = %v", err)
				return
			}
			_, err = rk.Unmarshal(data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
