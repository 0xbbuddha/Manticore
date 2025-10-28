package utils_test

import (
	"bytes"
	"testing"

	"github.com/TheManticoreProject/Manticore/utils"
)

func TestReadUntilNullTerminator(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		expected  []byte
		bytesRead int
	}{
		{
			name:      "empty input",
			input:     []byte{},
			expected:  []byte{},
			bytesRead: 0,
		},
		{
			name:      "no null terminator",
			input:     []byte{'a', 'b', 'c'},
			expected:  []byte{'a', 'b', 'c'},
			bytesRead: 3,
		},
		{
			name:      "null terminator at end",
			input:     []byte{'a', 'b', 'c', 0},
			expected:  []byte{'a', 'b', 'c'},
			bytesRead: 4,
		},
		{
			name:      "null terminator in middle",
			input:     []byte{'a', 0, 'c'},
			expected:  []byte{'a'},
			bytesRead: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, bytesRead := utils.ReadUntilNullTerminator(tt.input)
			if !bytes.Equal(got, tt.expected) {
				t.Errorf("ReadUntilNullTerminator() got = %v, want %v", got, tt.expected)
			}
			if bytesRead != tt.bytesRead {
				t.Errorf("ReadUntilNullTerminator() bytesRead = %v, want %v", bytesRead, tt.bytesRead)
			}
		})
	}
}

func TestReadUntilNullTerminatorUTF16(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		expected  []byte
		bytesRead int
	}{
		{
			name:      "empty input",
			input:     []byte{},
			expected:  []byte{},
			bytesRead: 0,
		},
		{
			name:      "no null terminator",
			input:     []byte{'a', 0, 'b', 0, 'c', 0},
			expected:  []byte{'a', 0, 'b', 0, 'c', 0},
			bytesRead: 6,
		},
		{
			name:      "null terminator at end",
			input:     []byte{'a', 0, 'b', 0, 0, 0},
			expected:  []byte{'a', 0, 'b', 0},
			bytesRead: 6,
		},
		{
			name:      "null terminator in middle",
			input:     []byte{'a', 0, 0, 0, 'c', 0},
			expected:  []byte{'a', 0},
			bytesRead: 4,
		},
		{
			name:      "odd length input",
			input:     []byte{'a', 0, 'b'},
			expected:  []byte{'a', 0, 'b'},
			bytesRead: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, bytesRead := utils.ReadUntilNullTerminatorUTF16(tt.input)
			if !bytes.Equal(got, tt.expected) {
				t.Errorf("ReadUntilNullTerminatorUTF16() got = %v, want %v", got, tt.expected)
			}
			if bytesRead != tt.bytesRead {
				t.Errorf("ReadUntilNullTerminatorUTF16() bytesRead = %v, want %v", bytesRead, tt.bytesRead)
			}
		})
	}
}
