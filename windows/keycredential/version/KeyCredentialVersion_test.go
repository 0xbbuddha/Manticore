package version_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/TheManticoreProject/Manticore/windows/keycredential/version"
)

func TestKeyCredentialVersion_Unmarshal(t *testing.T) {
	tests := []struct {
		input    []byte
		expected version.KeyCredentialVersion
	}{
		{[]byte{0x00, 0x00, 0x00, 0x00}, version.KeyCredentialVersion{Value: version.KeyCredentialVersion_0}},
		{[]byte{0x00, 0x01, 0x00, 0x00}, version.KeyCredentialVersion{Value: version.KeyCredentialVersion_1}},
		{[]byte{0x00, 0x02, 0x00, 0x00}, version.KeyCredentialVersion{Value: version.KeyCredentialVersion_2}},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("input: %v", test.input), func(t *testing.T) {
			var kcv version.KeyCredentialVersion
			_, err := kcv.Unmarshal(test.input)
			if err != nil {
				t.Errorf("\n| Expected : no error \n| But got  : %v", err)
			}
			if kcv.Value != test.expected.Value {
				t.Errorf("\n| Expected : 0x%08X \n| But got  : 0x%08X", test.expected.Value, kcv.Value)
			}
		})
	}
}

func TestKeyCredentialVersion_String(t *testing.T) {
	tests := []struct {
		version  version.KeyCredentialVersion
		expected string
	}{
		{version.KeyCredentialVersion{Value: version.KeyCredentialVersion_0}, "KeyCredential_v0"},
		{version.KeyCredentialVersion{Value: version.KeyCredentialVersion_1}, "KeyCredential_v1"},
		{version.KeyCredentialVersion{Value: version.KeyCredentialVersion_2}, "KeyCredential_v2"},
		{version.KeyCredentialVersion{Value: 0x00000300}, "Unknown version: 0x00000300"},
	}

	for _, test := range tests {
		t.Run(test.expected, func(t *testing.T) {
			result := test.version.String()
			if result != test.expected {
				t.Errorf("Expected %s, but got %s", test.expected, result)
			}
		})
	}
}

func TestKeyCredentialVersion_Marshal(t *testing.T) {
	tests := []struct {
		version  version.KeyCredentialVersion
		expected []byte
	}{
		{version.KeyCredentialVersion{Value: version.KeyCredentialVersion_0}, []byte{0x00, 0x00, 0x00, 0x00}},
		{version.KeyCredentialVersion{Value: version.KeyCredentialVersion_1}, []byte{0x00, 0x01, 0x00, 0x00}},
		{version.KeyCredentialVersion{Value: version.KeyCredentialVersion_2}, []byte{0x00, 0x02, 0x00, 0x00}},
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("version: %d", test.version.Value), func(t *testing.T) {
			result, err := test.version.Marshal()
			if err != nil {
				t.Errorf("Expected no error, but got %v", err)
			}
			if !bytes.Equal(result, test.expected) {
				t.Errorf("Expected %v, but got %v", test.expected, result)
			}
		})
	}
}
