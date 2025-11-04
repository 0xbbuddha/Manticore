package uuid_v3_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/crypto/uuid/uuid_v1"
	"github.com/TheManticoreProject/Manticore/crypto/uuid/uuid_v3"
)

func TestUUIDv3(t *testing.T) {
	tests := []struct {
		name           string
		namespace      string
		domain         string
		wantUUIDstring string
		wantErr        bool
	}{
		// DNS namespace
		{
			name:           "UUID v3 - DNS namespace - unicorn-utterances.com",
			namespace:      uuid_v3.UUIDv3NamespaceDNS,
			domain:         "unicorn-utterances.com",
			wantUUIDstring: "8d9aeee5-d9ad-3934-84f4-ac533183424d",
			wantErr:        false,
		},
		{
			name:           "UUID v3 - DNS namespace - podaliri.us",
			namespace:      uuid_v3.UUIDv3NamespaceDNS,
			domain:         "podaliri.us",
			wantUUIDstring: "c0819443-a39c-3e47-a949-303520cf9661",
			wantErr:        false,
		},
		{
			name:           "UUID v3 - DNS namespace - manticore.local",
			namespace:      uuid_v3.UUIDv3NamespaceDNS,
			domain:         "manticore.local",
			wantUUIDstring: "17aae0f3-3230-34cf-ad4c-ca7b64fecff6",
			wantErr:        false,
		},
		// URL namespace
		{
			name:           "UUID v3 - URL namespace - https://podalirius.net/en/",
			namespace:      uuid_v3.UUIDv3NamespaceURL,
			domain:         "https://podalirius.net/en/",
			wantUUIDstring: "3a07e56c-4414-3f98-9f70-db5caaceae2f",
			wantErr:        false,
		},
		{
			name:           "UUID v3 - URL namespace - https://example.com/",
			namespace:      uuid_v3.UUIDv3NamespaceURL,
			domain:         "https://example.com/",
			wantUUIDstring: "b9dcdff8-af4a-365d-8043-0f8361942709",
			wantErr:        false,
		},
		{
			name:           "UUID v3 - URL namespace - https://example.com/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/wow_long_url_test.txt",
			namespace:      uuid_v3.UUIDv3NamespaceURL,
			domain:         "https://example.com/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/wow_long_url_test.txt",
			wantUUIDstring: "16deecaf-5091-344f-be00-2374341aac77",
			wantErr:        false,
		},
		// OID namespace
		{
			name:           "OID UUID v3 - simple OID: 1.3.6.1.4.1",
			namespace:      uuid_v3.UUIDv3NamespaceOID,
			domain:         "1.3.6.1.4.1",
			wantUUIDstring: "ef89b4fd-cc82-39f4-8098-b58dd72a496c",
			wantErr:        false,
		},
		{
			name:           "OID UUID v3 - extended OID: 2.5.4.3",
			namespace:      uuid_v3.UUIDv3NamespaceOID,
			domain:         "2.5.4.3",
			wantUUIDstring: "2fb63d6b-4dc4-38c6-9b71-01293c42d480",
			wantErr:        false,
		},
		{
			name:           "OID UUID v3 - long OID: 1.2.840.113549.1.1.5",
			namespace:      uuid_v3.UUIDv3NamespaceOID,
			domain:         "1.2.840.113549.1.1.5",
			wantUUIDstring: "ccb0e5e3-1b5c-3f20-a4ce-71ffd870f61c",
			wantErr:        false,
		},
		// X500 namespace
		{
			name:           "UUID v3 - X500 namespace - simple X500 DN example (CN=example.com,O=Example Corp,C=US)",
			namespace:      uuid_v3.UUIDv3NamespaceX500,
			domain:         "CN=example.com,O=Example Corp,C=US",
			wantUUIDstring: "83e63937-f1ff-3820-9eb6-597d657bae21",
			wantErr:        false,
		},
		{
			name:           "UUID v3 - X500 namespace - person name DN (CN=John Doe,OU=Engineering,O=Acme Inc,C=US)",
			namespace:      uuid_v3.UUIDv3NamespaceX500,
			domain:         "CN=John Doe,OU=Engineering,O=Acme Inc,C=US",
			wantUUIDstring: "402e41e2-9e43-31d1-b9ad-2b910189f6f4",
			wantErr:        false,
		},
		{
			name:           "UUID v3 - X500 namespace - complex DN with email (CN=user user,CN=Users,DC=MANTICORE,DC=LOCAL)",
			namespace:      uuid_v3.UUIDv3NamespaceX500,
			domain:         "CN=user user,CN=Users,DC=MANTICORE,DC=LOCAL",
			wantUUIDstring: "cf963c07-2a75-3453-b35e-eedc53156b7a",
			wantErr:        false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var u uuid_v3.UUIDv3

			ui := uuid_v1.UUIDv1{}
			ui.FromString(test.namespace)
			u.Namespace = &ui
			u.Name = test.domain

			_, err := u.Marshal()
			if err != nil {
				t.Errorf("Marshal() error = %v", err)
			}

			if u.String() != test.wantUUIDstring {
				t.Errorf("UUIDv3.String() \n\tgot  %v\n\twant %v", u.String(), test.wantUUIDstring)
			}
		})
	}
}
