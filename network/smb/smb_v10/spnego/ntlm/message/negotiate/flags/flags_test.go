package flags_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/network/smb/smb_v10/spnego/ntlm/message/negotiate/flags"
)

func TestNegotiateFlagsString(t *testing.T) {
	tests := []struct {
		flags    flags.NegotiateFlags
		expected string
	}{
		{
			flags:    flags.NTLMSSP_NEGOTIATE_UNICODE,
			expected: "NTLMSSP_NEGOTIATE_UNICODE",
		},
		{
			flags:    flags.NTLMSSP_NEGOTIATE_UNICODE | flags.NTLMSSP_NEGOTIATE_OEM,
			expected: "NTLMSSP_NEGOTIATE_UNICODE|NTLMSSP_NEGOTIATE_OEM",
		},
		{
			flags:    flags.NTLMSSP_NEGOTIATE_UNICODE | flags.NTLMSSP_NEGOTIATE_OEM | flags.NTLMSSP_REQUEST_TARGET,
			expected: "NTLMSSP_NEGOTIATE_UNICODE|NTLMSSP_NEGOTIATE_OEM|NTLMSSP_REQUEST_TARGET",
		},
	}

	for _, test := range tests {
		result := test.flags.String()
		if result != test.expected {
			t.Errorf("Expected %s, got %s", test.expected, result)
		}
	}
}

func TestNegotiateFlagsHas(t *testing.T) {
	tests := []struct {
		flags    flags.NegotiateFlags
		check    flags.NegotiateFlags
		expected bool
	}{
		{
			flags:    flags.NTLMSSP_NEGOTIATE_UNICODE,
			check:    flags.NTLMSSP_NEGOTIATE_UNICODE,
			expected: true,
		},
		{
			flags:    flags.NTLMSSP_NEGOTIATE_UNICODE | flags.NTLMSSP_NEGOTIATE_OEM,
			check:    flags.NTLMSSP_NEGOTIATE_OEM,
			expected: true,
		},
		{
			flags:    flags.NTLMSSP_NEGOTIATE_UNICODE,
			check:    flags.NTLMSSP_NEGOTIATE_OEM,
			expected: false,
		},
	}

	for _, test := range tests {
		result := test.flags.HasFlag(test.check)
		if result != test.expected {
			t.Errorf("Expected %v, got %v", test.expected, result)
		}
	}
}
