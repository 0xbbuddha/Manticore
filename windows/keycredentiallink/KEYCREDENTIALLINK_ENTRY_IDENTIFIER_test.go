package keycredentiallink

import (
	"testing"
)

func TestKEYCREDENTIALLINK_ENTRY_IDENTIFIER_Unmarshal(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		expectedString string
		want           KEYCREDENTIALLINK_ENTRY_IDENTIFIER
	}{
		{name: "Valid KEYCREDENTIALLINK_ENTRY_IDENTIFIER", data: []byte{0x01}, expectedString: "KeyID", want: KEYCREDENTIALLINK_ENTRY_IDENTIFIER{Value: 0x01}},
		{name: "Valid KEYCREDENTIALLINK_ENTRY_IDENTIFIER", data: []byte{0x02}, expectedString: "KeyHash", want: KEYCREDENTIALLINK_ENTRY_IDENTIFIER{Value: 0x02}},
		{name: "Valid KEYCREDENTIALLINK_ENTRY_IDENTIFIER", data: []byte{0x03}, expectedString: "KeyMaterial", want: KEYCREDENTIALLINK_ENTRY_IDENTIFIER{Value: 0x03}},
		{name: "Valid KEYCREDENTIALLINK_ENTRY_IDENTIFIER", data: []byte{0x04}, expectedString: "KeyUsage", want: KEYCREDENTIALLINK_ENTRY_IDENTIFIER{Value: 0x04}},
		{name: "Valid KEYCREDENTIALLINK_ENTRY_IDENTIFIER", data: []byte{0x05}, expectedString: "KeySource", want: KEYCREDENTIALLINK_ENTRY_IDENTIFIER{Value: 0x05}},
		{name: "Valid KEYCREDENTIALLINK_ENTRY_IDENTIFIER", data: []byte{0x06}, expectedString: "DeviceId", want: KEYCREDENTIALLINK_ENTRY_IDENTIFIER{Value: 0x06}},
		{name: "Valid KEYCREDENTIALLINK_ENTRY_IDENTIFIER", data: []byte{0x07}, expectedString: "CustomKeyInformation", want: KEYCREDENTIALLINK_ENTRY_IDENTIFIER{Value: 0x07}},
		{name: "Valid KEYCREDENTIALLINK_ENTRY_IDENTIFIER", data: []byte{0x08}, expectedString: "KeyApproximateLastLogonTimeStamp", want: KEYCREDENTIALLINK_ENTRY_IDENTIFIER{Value: 0x08}},
		{name: "Valid KEYCREDENTIALLINK_ENTRY_IDENTIFIER", data: []byte{0x09}, expectedString: "KeyCreationTime", want: KEYCREDENTIALLINK_ENTRY_IDENTIFIER{Value: 0x09}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := KEYCREDENTIALLINK_ENTRY_IDENTIFIER{}
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
