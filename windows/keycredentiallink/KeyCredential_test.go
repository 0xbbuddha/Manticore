package keycredentiallink_test

// func TestKeyCredential_Unmarshal(t *testing.T) {
// 	tests := []struct {
// 		name                       string
// 		msDsKeyCredentialLinkValue string
// 		expectedKC                 *keycredentiallink.KeyCredential
// 		wantErr                    bool
// 	}{
// 		{
// 			name:                       "Valid KeyCredential with specific identifier",
// 			msDsKeyCredentialLinkValue: "B:10:9012345678:CN=POC,CN=Computers,DC=MANTICORE,DC=local",
// 			expectedKC:                 nil,
// 			wantErr:                    true,
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			kc := keycredentiallink.NewKeyCredential(
// 				version.KeyCredentialVersion{Value: version.KeyCredentialVersion_1},
// 				"",
// 				&keys.BCRYPT_RSA_PUBLIC_KEY{},
// 				guid.GUID{},
// 				utils.DateTime{},
// 				utils.DateTime{},
// 			)

// 			dnb := ldap.DNWithBinary{}
// 			bytesRead, err := dnb.Unmarshal([]byte(tt.msDsKeyCredentialLinkValue))
// 			if err != nil {
// 				if !tt.wantErr {
// 					t.Errorf("Unmarshal() error = %v", err)
// 				}
// 				return
// 			}
// 			if bytesRead != len([]byte(tt.msDsKeyCredentialLinkValue)) {
// 				t.Errorf("Unmarshal() bytesRead = %v, want %v", bytesRead, len([]byte(tt.msDsKeyCredentialLinkValue)))
// 				return
// 			}

// 			_, err = kc.Unmarshal(dnb.BinaryData)
// 			if (err != nil) != tt.wantErr {
// 				t.Errorf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
// 				return
// 			}
// 		})
// 	}
// }
