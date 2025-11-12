package keycredentiallink_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/windows/keycredentiallink"
)

func TestKEYCREDENTIALLINK_ENTRY_IDENTIFIER_Unmarshal(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		expectedString string
		want           keycredentiallink.KEYCREDENTIALLINK_ENTRY_IDENTIFIER
	}{
		{name: "Valid KEYCREDENTIALLINK_ENTRY_IDENTIFIER", data: []byte{0x01}, expectedString: "KeyID", want: keycredentiallink.KEYCREDENTIALLINK_ENTRY_IDENTIFIER(0x01)},
		{name: "Valid KEYCREDENTIALLINK_ENTRY_IDENTIFIER", data: []byte{0x02}, expectedString: "KeyHash", want: keycredentiallink.KEYCREDENTIALLINK_ENTRY_IDENTIFIER(0x02)},
		{name: "Valid KEYCREDENTIALLINK_ENTRY_IDENTIFIER", data: []byte{0x03}, expectedString: "KeyMaterial", want: keycredentiallink.KEYCREDENTIALLINK_ENTRY_IDENTIFIER(0x03)},
		{name: "Valid KEYCREDENTIALLINK_ENTRY_IDENTIFIER", data: []byte{0x04}, expectedString: "KeyUsage", want: keycredentiallink.KEYCREDENTIALLINK_ENTRY_IDENTIFIER(0x04)},
		{name: "Valid KEYCREDENTIALLINK_ENTRY_IDENTIFIER", data: []byte{0x05}, expectedString: "KeySource", want: keycredentiallink.KEYCREDENTIALLINK_ENTRY_IDENTIFIER(0x05)},
		{name: "Valid KEYCREDENTIALLINK_ENTRY_IDENTIFIER", data: []byte{0x06}, expectedString: "DeviceId", want: keycredentiallink.KEYCREDENTIALLINK_ENTRY_IDENTIFIER(0x06)},
		{name: "Valid KEYCREDENTIALLINK_ENTRY_IDENTIFIER", data: []byte{0x07}, expectedString: "CustomKeyInformation", want: keycredentiallink.KEYCREDENTIALLINK_ENTRY_IDENTIFIER(0x07)},
		{name: "Valid KEYCREDENTIALLINK_ENTRY_IDENTIFIER", data: []byte{0x08}, expectedString: "KeyApproximateLastLogonTimeStamp", want: keycredentiallink.KEYCREDENTIALLINK_ENTRY_IDENTIFIER(0x08)},
		{name: "Valid KEYCREDENTIALLINK_ENTRY_IDENTIFIER", data: []byte{0x09}, expectedString: "KeyCreationTime", want: keycredentiallink.KEYCREDENTIALLINK_ENTRY_IDENTIFIER(0x09)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := keycredentiallink.KEYCREDENTIALLINK_ENTRY_IDENTIFIER(0x00)
			got.Unmarshal(tt.data)
			if !got.Equal(&tt.want) {
				t.Errorf("KEYCREDENTIALLINK_ENTRY_IDENTIFIER.Unmarshal() = %v, want %v", got, tt.want)
			}
			if got.String() != tt.expectedString {
				t.Errorf("KEYCREDENTIALLINK_ENTRY_IDENTIFIER.String() = %v, want %v", got.String(), tt.expectedString)
			}
		})
	}
}
