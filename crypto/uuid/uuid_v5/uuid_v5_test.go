package uuid_v5_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/crypto/uuid/uuid_v1"
	"github.com/TheManticoreProject/Manticore/crypto/uuid/uuid_v5"
)

func TestUUIDv5(t *testing.T) {
	tests := []struct {
		name           string
		namespace      string
		domain         string
		wantUUIDstring string
		wantErr        bool
	}{
		// DNS namespace
		{
			name:           "UUID v5 - DNS namespace - unicorn-utterances.com",
			namespace:      uuid_v5.UUIDv5NamespaceDNS,
			domain:         "unicorn-utterances.com",
			wantUUIDstring: "6b5eb089-463b-5cfe-a881-80f5fd6545b0",
			wantErr:        false,
		},
		{
			name:           "UUID v5 - DNS namespace - podaliri.us",
			namespace:      uuid_v5.UUIDv5NamespaceDNS,
			domain:         "podaliri.us",
			wantUUIDstring: "cb6bd3bc-37e1-5c61-bf29-e60111c05904",
			wantErr:        false,
		},
		{
			name:           "UUID v5 - DNS namespace - manticore.local",
			namespace:      uuid_v5.UUIDv5NamespaceDNS,
			domain:         "manticore.local",
			wantUUIDstring: "fb0174a9-fd2e-5a2f-b6ce-18a0aadedb2a",
			wantErr:        false,
		},
		// URL namespace
		{
			name:           "UUID v5 - URL namespace - https://podalirius.net/en/",
			namespace:      uuid_v5.UUIDv5NamespaceURL,
			domain:         "https://podalirius.net/en/",
			wantUUIDstring: "5abc9551-ad61-5e0b-92f1-45809c670d30",
			wantErr:        false,
		},
		{
			name:           "UUID v5 - URL namespace - https://example.com/",
			namespace:      uuid_v5.UUIDv5NamespaceURL,
			domain:         "https://example.com/",
			wantUUIDstring: "dd2c1780-811a-5296-81c5-178a0ef488bc",
			wantErr:        false,
		},
		{
			name:           "UUID v5 - URL namespace - https://example.com/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/wow_long_url_test.txt",
			namespace:      uuid_v5.UUIDv5NamespaceURL,
			domain:         "https://example.com/a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/wow_long_url_test.txt",
			wantUUIDstring: "17947aef-7a89-576f-8950-367f3ab2eb4e",
			wantErr:        false,
		},
		// OID namespace
		{
			name:           "OID UUID v5 - simple OID: 1.3.6.1.4.1",
			namespace:      uuid_v5.UUIDv5NamespaceOID,
			domain:         "1.3.6.1.4.1",
			wantUUIDstring: "106dd502-8b3e-50db-80ed-1134f5c18eae",
			wantErr:        false,
		},
		{
			name:           "OID UUID v5 - extended OID: 2.5.4.3",
			namespace:      uuid_v5.UUIDv5NamespaceOID,
			domain:         "2.5.4.3",
			wantUUIDstring: "8fbdd450-9155-5273-9d11-347a949ee1c1",
			wantErr:        false,
		},
		{
			name:           "OID UUID v5 - long OID: 1.2.840.113549.1.1.5",
			namespace:      uuid_v5.UUIDv5NamespaceOID,
			domain:         "1.2.840.113549.1.1.5",
			wantUUIDstring: "762e65b4-848b-5fa0-bf93-0b09162152d4",
			wantErr:        false,
		},
		// X500 namespace
		{
			name:           "UUID v5 - X500 namespace - simple X500 DN example (CN=example.com,O=Example Corp,C=US)",
			namespace:      uuid_v5.UUIDv5NamespaceX500,
			domain:         "CN=example.com,O=Example Corp,C=US",
			wantUUIDstring: "8f0cbdb1-736b-59fb-917b-2bcf5b8f965f",
			wantErr:        false,
		},
		{
			name:           "UUID v5 - X500 namespace - person name DN (CN=John Doe,OU=Engineering,O=Acme Inc,C=US)",
			namespace:      uuid_v5.UUIDv5NamespaceX500,
			domain:         "CN=John Doe,OU=Engineering,O=Acme Inc,C=US",
			wantUUIDstring: "806ebb90-a122-5027-84e0-5a8fe718aad1",
			wantErr:        false,
		},
		{
			name:           "UUID v5 - X500 namespace - complex DN with email (CN=user user,CN=Users,DC=MANTICORE,DC=LOCAL)",
			namespace:      uuid_v5.UUIDv5NamespaceX500,
			domain:         "CN=user user,CN=Users,DC=MANTICORE,DC=LOCAL",
			wantUUIDstring: "769b2415-682a-515d-b020-1447ceafb8de",
			wantErr:        false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var u uuid_v5.UUIDv5

			ui := uuid_v1.UUIDv1{}
			ui.FromString(test.namespace)
			u.Namespace = &ui
			u.Name = test.domain

			_, err := u.Marshal()
			if err != nil {
				t.Errorf("Marshal() error = %v", err)
			}

			if u.String() != test.wantUUIDstring {
				t.Errorf("UUIDv5.String() \n\tgot  %v\n\twant %v", u.String(), test.wantUUIDstring)
			}
		})
	}
}
