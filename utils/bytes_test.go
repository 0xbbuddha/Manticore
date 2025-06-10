package utils_test

import (
	"bytes"
	"testing"

	"github.com/TheManticoreProject/Manticore/utils"
)

func TestReadUntilNullTerminator(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
		offset   int
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: []byte{},
			offset:   0,
		},
		{
			name:     "no null terminator",
			input:    []byte{'a', 'b', 'c'},
			expected: []byte{'a', 'b', 'c'},
			offset:   3,
		},
		{
			name:     "null terminator at end",
			input:    []byte{'a', 'b', 'c', 0},
			expected: []byte{'a', 'b', 'c'},
			offset:   3,
		},
		{
			name:     "null terminator in middle",
			input:    []byte{'a', 0, 'c'},
			expected: []byte{'a'},
			offset:   1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, offset := utils.ReadUntilNullTerminator(tt.input)
			if !bytes.Equal(got, tt.expected) {
				t.Errorf("ReadUntilNullTerminator() got = %v, want %v", got, tt.expected)
			}
			if offset != tt.offset {
				t.Errorf("ReadUntilNullTerminator() offset = %v, want %v", offset, tt.offset)
			}
		})
	}
}

func TestReadUntilNullTerminatorUTF16(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
		offset   int
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: []byte{},
			offset:   0,
		},
		{
			name:     "no null terminator",
			input:    []byte{'a', 0, 'b', 0, 'c', 0},
			expected: []byte{'a', 0, 'b', 0, 'c', 0},
			offset:   6,
		},
		{
			name:     "null terminator at end",
			input:    []byte{'a', 0, 'b', 0, 0, 0},
			expected: []byte{'a', 0, 'b', 0},
			offset:   4,
		},
		{
			name:     "null terminator in middle",
			input:    []byte{'a', 0, 0, 0, 'c', 0},
			expected: []byte{'a', 0},
			offset:   2,
		},
		{
			name:     "odd length input",
			input:    []byte{'a', 0, 'b'},
			expected: []byte{'a', 0, 'b'},
			offset:   2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, offset := utils.ReadUntilNullTerminatorUTF16(tt.input)
			if !bytes.Equal(got, tt.expected) {
				t.Errorf("ReadUntilNullTerminatorUTF16() got = %v, want %v", got, tt.expected)
			}
			if offset != tt.offset {
				t.Errorf("ReadUntilNullTerminatorUTF16() offset = %v, want %v", offset, tt.offset)
			}
		})
	}
}
