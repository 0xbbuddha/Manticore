package utils_test

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/TheManticoreProject/Manticore/windows/keycredential/key/source"
	"github.com/TheManticoreProject/Manticore/windows/keycredential/utils"
	"github.com/TheManticoreProject/Manticore/windows/keycredential/version"
)

func TestConvertFromBinaryIdentifier(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		version  version.KeyCredentialVersion
		expected string
	}{
		{
			name:     "Version 0 hex encoding",
			input:    []byte{0x12, 0x34, 0x56},
			version:  version.KeyCredentialVersion{Value: version.KeyCredentialVersion_0},
			expected: "123456",
		},
		{
			name:     "Version 1 hex encoding",
			input:    []byte{0x12, 0x34, 0x56},
			version:  version.KeyCredentialVersion{Value: version.KeyCredentialVersion_1},
			expected: "123456",
		},
		{
			name:     "Version 2 base64 encoding",
			input:    []byte{0x12, 0x34, 0x56},
			version:  version.KeyCredentialVersion{Value: version.KeyCredentialVersion_2},
			expected: base64.StdEncoding.EncodeToString([]byte{0x12, 0x34, 0x56}),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := utils.ConvertFromBinaryIdentifier(tc.input, tc.version)
			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
		})
	}
}

func TestConvertFromBinaryTime(t *testing.T) {
	// Create test timestamp (2022-03-15 12:00:03 UTC)
	testTimeBytes := []byte{0x80, 0xa3, 0x22, 0x34, 0x64, 0x38, 0xd8, 0x01}
	testTimeStruct := time.Date(2022, 3, 15, 12, 0, 3, 0, time.UTC)

	testCases := []struct {
		name     string
		input    []byte
		source   source.KeySource
		version  version.KeyCredentialVersion
		expected time.Time
	}{
		{
			name:     "Version 0 AD source",
			input:    testTimeBytes,
			source:   source.KeySource{Value: source.KeySource_AD},
			version:  version.KeyCredentialVersion{Value: version.KeyCredentialVersion_0},
			expected: testTimeStruct,
		},
		{
			name:     "Version 1 AD source",
			input:    testTimeBytes,
			source:   source.KeySource{Value: source.KeySource_AD},
			version:  version.KeyCredentialVersion{Value: version.KeyCredentialVersion_1},
			expected: testTimeStruct,
		},
		{
			name:     "Version 2 AD source",
			input:    testTimeBytes,
			source:   source.KeySource{Value: source.KeySource_AD},
			version:  version.KeyCredentialVersion{Value: version.KeyCredentialVersion_2},
			expected: testTimeStruct,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := utils.ConvertFromBinaryTime(tc.input, tc.source, tc.version)
			if !result.Time.Equal(tc.expected) {
				t.Errorf("Expected %v, got %v", tc.expected, result.Time)
			}
		})
	}
}

func TestConvertToBinaryTime(t *testing.T) {
	// Create test timestamp (2022-03-15 12:00:03 UTC)
	testTimeBytes := []byte{0x80, 0xa3, 0x22, 0x34, 0x64, 0x38, 0xd8, 0x01}
	testTimeStruct := time.Date(2022, 3, 15, 12, 0, 3, 0, time.UTC)

	testCases := []struct {
		name    string
		input   []byte
		source  source.KeySource
		version version.KeyCredentialVersion
	}{
		{
			name:    "Version 0 AD source",
			input:   testTimeBytes,
			source:  source.KeySource{Value: source.KeySource_AD},
			version: version.KeyCredentialVersion{Value: version.KeyCredentialVersion_0},
		},
		{
			name:    "Version 1 AD source",
			input:   testTimeBytes,
			source:  source.KeySource{Value: source.KeySource_AD},
			version: version.KeyCredentialVersion{Value: version.KeyCredentialVersion_1},
		},
		{
			name:    "Version 2 AD source",
			input:   testTimeBytes,
			source:  source.KeySource{Value: source.KeySource_AD},
			version: version.KeyCredentialVersion{Value: version.KeyCredentialVersion_2},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			converted := utils.ConvertFromBinaryTime(tc.input, tc.source, tc.version)
			if !converted.Time.Equal(testTimeStruct) {
				t.Errorf("Time conversion mismatch. \n | Expected '%v'\n | utils.ConvertToBinaryTime(_) = %v\n | final decoded time '%v'", testTimeStruct, tc.input, converted.Time)
			}
		})
	}
}
