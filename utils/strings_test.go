package utils_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/utils"
)

func TestPadStringLeft(t *testing.T) {
	tests := []struct {
		input    string
		padChar  string
		length   int
		expected string
	}{
		{"hello", "*", 8, "***hello"},
		{"world", "-", 10, "-----world"},
		{"test", " ", 6, "  test"},
		{"", "#", 5, "#####"},
		{"short", "0", 5, "short"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := utils.PadStringLeft(tt.input, tt.padChar, tt.length)
			if result != tt.expected {
				t.Errorf("PadStringLeft(%q, %q, %d) = %q; want %q", tt.input, tt.padChar, tt.length, result, tt.expected)
			}
		})
	}
}

func TestSizeInBytes(t *testing.T) {
	tests := []struct {
		size     uint64
		expected string
	}{
		{512, "512 bytes"},
		{1024, "1.00 KiB"},
		{1048576, "1.00 MiB"},
		{1073741824, "1.00 GiB"},
		{1099511627776, "1.00 TiB"},
		{1125899906842624, "1.00 PiB"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := utils.SizeInBytes(tt.size)
			if result != tt.expected {
				t.Errorf("SizeInBytes(%d) = %q; want %q", tt.size, result, tt.expected)
			}
		})
	}
}

func TestEndsWithNullTerminator(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"hello\x00", true},
		{"world", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := utils.EndsWithNullTerminator(tt.input)
			if result != tt.expected {
				t.Errorf("EndsWithNullTerminator(%q) = %v; want %v", tt.input, result, tt.expected)
			}
		})
	}
}

func TestEndsWithNullTerminatorUTF16(t *testing.T) {
	tests := []struct {
		testName string
		input    []byte
		expected bool
	}{
		{"UTF16-LE hello with null terminator", []byte("h\x00e\x00l\x00l\x00o\x00\x00\x00"), true},
		{"UTF16-LE hello without null terminator", []byte("h\x00e\x00l\x00l\x00o\x00"), false},
		{"UTF16-LE world with null terminator", []byte("\x00w\x00o\x00r\x00l\x00d\x00\x00"), true},
		{"UTF16-LE world without null terminator", []byte("\x00w\x00o\x00r\x00l\x00d"), false},
	}

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			result := utils.EndsWithNullTerminatorUTF16(tt.input)
			if result != tt.expected {
				t.Errorf("EndsWithNullTerminatorUTF16(%q) = %v; want %v", tt.input, result, tt.expected)
			}
		})
	}
}
