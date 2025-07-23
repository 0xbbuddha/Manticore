package avpair_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/network/smb/smb_v10/spnego/ntlm/avpair"
)

func TestAvIdString(t *testing.T) {
	tests := []struct {
		name     string
		id       avpair.AvId
		expected string
	}{
		{
			name:     "MsvAvEOL",
			id:       avpair.MsvAvEOL,
			expected: "MsvAvEOL",
		},
		{
			name:     "MsvAvNbComputerName",
			id:       avpair.MsvAvNbComputerName,
			expected: "MsvAvNbComputerName",
		},
		{
			name:     "MsvAvNbDomainName",
			id:       avpair.MsvAvNbDomainName,
			expected: "MsvAvNbDomainName",
		},
		{
			name:     "MsvAvDnsComputerName",
			id:       avpair.MsvAvDnsComputerName,
			expected: "MsvAvDnsComputerName",
		},
		{
			name:     "MsvAvDnsDomainName",
			id:       avpair.MsvAvDnsDomainName,
			expected: "MsvAvDnsDomainName",
		},
		{
			name:     "MsvAvDnsTreeName",
			id:       avpair.MsvAvDnsTreeName,
			expected: "MsvAvDnsTreeName",
		},
		{
			name:     "MsvAvFlags",
			id:       avpair.MsvAvFlags,
			expected: "MsvAvFlags",
		},
		{
			name:     "MsvAvTimestamp",
			id:       avpair.MsvAvTimestamp,
			expected: "MsvAvTimestamp",
		},
		{
			name:     "MsvAvSingleHost",
			id:       avpair.MsvAvSingleHost,
			expected: "MsvAvSingleHost",
		},
		{
			name:     "MsvAvTargetName",
			id:       avpair.MsvAvTargetName,
			expected: "MsvAvTargetName",
		},
		{
			name:     "MsvAvChannelBindings",
			id:       avpair.MsvAvChannelBindings,
			expected: "MsvAvChannelBindings",
		},
		{
			name:     "Unknown",
			id:       0xFFFF,
			expected: "Unknown(0xffff)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.id.String(); got != tt.expected {
				t.Errorf("AvId.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}
