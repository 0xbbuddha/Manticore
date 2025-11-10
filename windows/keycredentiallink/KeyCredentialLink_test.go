package keycredentiallink_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/network/ldap"
	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink"
)

func TestKeyCredential_Unmarshal(t *testing.T) {
	tests := []struct {
		name                       string
		msDsKeyCredentialLinkValue string
		wantErr                    bool
	}{
		{
			name:                       "Valid KeyCredential with specific identifier",
			msDsKeyCredentialLinkValue: "B:10:9012345678:CN=POC,CN=Computers,DC=MANTICORE,DC=local",
			wantErr:                    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dnb := ldap.DNWithBinary{}
			bytesRead, err := dnb.Unmarshal([]byte(tt.msDsKeyCredentialLinkValue))
			if err != nil {
				if !tt.wantErr {
					t.Errorf("Unmarshal() error = %v", err)
				}
				return
			}
			if bytesRead != len([]byte(tt.msDsKeyCredentialLinkValue)) {
				t.Errorf("Unmarshal() bytesRead = %v, want %v", bytesRead, len([]byte(tt.msDsKeyCredentialLinkValue)))
				return
			}

			kcl := keycredentiallink.KeyCredentialLink{}
			_, err = kcl.Unmarshal(dnb.BinaryData)
			if (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}
