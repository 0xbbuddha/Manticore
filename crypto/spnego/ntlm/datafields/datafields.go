package datafields

import (
	"encoding/binary"
	"fmt"
)

// DataFields is the data fields of an NTLM message
type DataFields struct {
	// Len is the length of the data fields (in bytes)
	Len uint16

	// MaxLen is the maximum length of the data fields (in bytes)
	MaxLen uint16

	// BufferOffset is the offset of the buffer (in bytes)
	BufferOffset uint32
}

// Marshal serializes the DataFields into a byte slice
func (df *DataFields) Marshal() ([]byte, error) {
	data := make([]byte, 8)

	// Write Len (2 bytes)
	binary.LittleEndian.PutUint16(data[0:2], df.Len)

	// Write MaxLen (2 bytes)
	binary.LittleEndian.PutUint16(data[2:4], df.MaxLen)

	// Write BufferOffset (4 bytes)
	binary.LittleEndian.PutUint32(data[4:8], df.BufferOffset)

	return data, nil
}

// Unmarshal deserializes a byte slice into DataFields
func (df *DataFields) Unmarshal(data []byte) (int, error) {
	if len(data) < 8 {
		return 0, fmt.Errorf("data too short to be valid DataFields")
	}

	// Read Len (2 bytes)
	df.Len = binary.LittleEndian.Uint16(data[0:2])

	// Read MaxLen (2 bytes)
	df.MaxLen = binary.LittleEndian.Uint16(data[2:4])

	// Read BufferOffset (4 bytes)
	df.BufferOffset = binary.LittleEndian.Uint32(data[4:8])

	return 8, nil
}

// Equal compares two DataFields structs for equality
func (df *DataFields) Equal(other *DataFields) bool {
	return df.Len == other.Len &&
		df.MaxLen == other.MaxLen &&
		df.BufferOffset == other.BufferOffset
}
