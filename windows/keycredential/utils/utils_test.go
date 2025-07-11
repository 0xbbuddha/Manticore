package utils_test

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/TheManticoreProject/Manticore/windows/keycredential/key"
	"github.com/TheManticoreProject/Manticore/windows/keycredential/utils"
)

func TestConvertFromBinaryIdentifier(t *testing.T) {
	testCases := []struct {
		name     string
		input    []byte
		version  key.KeyCredentialVersion
		expected string
	}{
		{
			name:     "Version 0 hex encoding",
			input:    []byte{0x12, 0x34, 0x56},
			version:  key.KeyCredentialVersion{Value: key.KeyCredentialVersion_0},
			expected: "123456",
		},
		{
			name:     "Version 1 hex encoding",
			input:    []byte{0x12, 0x34, 0x56},
			version:  key.KeyCredentialVersion{Value: key.KeyCredentialVersion_1},
			expected: "123456",
		},
		{
			name:     "Version 2 base64 encoding",
			input:    []byte{0x12, 0x34, 0x56},
			version:  key.KeyCredentialVersion{Value: key.KeyCredentialVersion_2},
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
	testTime := []byte{0x00, 0x30, 0x03, 0x32, 0x13, 0x29, 0x13, 0x00}

	testCases := []struct {
		name     string
		input    []byte
		source   key.KeySource
		version  key.KeyCredentialVersion
		expected time.Time
	}{
		{
			name:     "Version 0 AD source",
			input:    testTime,
			source:   key.KeySource_AD,
			version:  key.KeyCredentialVersion{Value: key.KeyCredentialVersion_0},
			expected: time.Date(2022, 3, 15, 12, 0, 3, 0, time.UTC),
		},
		{
			name:     "Version 1 AD source",
			input:    testTime,
			source:   key.KeySource_AD,
			version:  key.KeyCredentialVersion{Value: key.KeyCredentialVersion_1},
			expected: time.Date(2022, 3, 15, 12, 0, 3, 0, time.UTC),
		},
		{
			name:     "Version 2 AD source",
			input:    testTime,
			source:   key.KeySource_AD,
			version:  key.KeyCredentialVersion{Value: key.KeyCredentialVersion_2},
			expected: time.Date(2022, 3, 15, 12, 0, 3, 0, time.UTC),
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
	testTime := time.Date(2022, 3, 15, 12, 0, 3, 0, time.UTC)

	testCases := []struct {
		name    string
		input   time.Time
		source  key.KeySource
		version key.KeyCredentialVersion
	}{
		{
			name:    "Version 0 AD source",
			input:   testTime,
			source:  key.KeySource_AD,
			version: key.KeyCredentialVersion{Value: key.KeyCredentialVersion_0},
		},
		{
			name:    "Version 1 AD source",
			input:   testTime,
			source:  key.KeySource_AD,
			version: key.KeyCredentialVersion{Value: key.KeyCredentialVersion_1},
		},
		{
			name:    "Version 2 AD source",
			input:   testTime,
			source:  key.KeySource_AD,
			version: key.KeyCredentialVersion{Value: key.KeyCredentialVersion_2},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := utils.ConvertToBinaryTime(tc.input, tc.source, tc.version)
			// Convert back and verify
			converted := utils.ConvertFromBinaryTime(result, tc.source, tc.version)
			if !converted.Time.Equal(tc.input) {
				t.Errorf("Time conversion mismatch. Expected %v, got %v", tc.input, converted.Time)
			}
		})
	}
}
