package avpair_test

import (
	"bytes"
	"testing"

	"github.com/TheManticoreProject/Manticore/crypto/spnego/ntlm/avpair"
)

func TestAvPairString(t *testing.T) {
	tests := []struct {
		avpair   avpair.AvPair
		expected string
	}{
		{
			avpair: avpair.AvPair{
				AvID:   avpair.MsvAvNbComputerName,
				AvLen:  4,
				AvData: []byte{0x01, 0x02, 0x03, 0x04},
			},
			expected: "AvId: MsvAvNbComputerName, AvLen: 4, AvData: [1 2 3 4]",
		},
		{
			avpair: avpair.AvPair{
				AvID:   avpair.MsvAvNbDomainName,
				AvLen:  3,
				AvData: []byte{0x05, 0x06, 0x07},
			},
			expected: "AvId: MsvAvNbDomainName, AvLen: 3, AvData: [5 6 7]",
		},
	}

	for _, test := range tests {
		if test.avpair.String() != test.expected {
			t.Errorf("Expected %s, got %s", test.expected, test.avpair.String())
		}
	}
}

func TestAvPairMarshal(t *testing.T) {
	tests := []struct {
		avpair   avpair.AvPair
		expected []byte
	}{
		{
			avpair: avpair.AvPair{
				AvID:   avpair.MsvAvNbComputerName,
				AvLen:  4,
				AvData: []byte{0x01, 0x02, 0x03, 0x04},
			},
			expected: []byte{0x01, 0x00, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04},
		},
		{
			avpair: avpair.AvPair{
				AvID:   avpair.MsvAvNbDomainName,
				AvLen:  3,
				AvData: []byte{0x05, 0x06, 0x07},
			},
			expected: []byte{0x02, 0x00, 0x03, 0x00, 0x05, 0x06, 0x07},
		},
	}

	for _, test := range tests {
		marshaled, err := test.avpair.Marshal()
		if err != nil {
			t.Fatalf("Unexpected error during marshal: %v", err)
		}

		if !bytes.Equal(marshaled, test.expected) {
			t.Errorf("Expected %v, got %v", test.expected, marshaled)
		}
	}
}

func TestAvPairUnmarshal(t *testing.T) {
	tests := []struct {
		data           []byte
		expectedAvID   avpair.AvId
		expectedAvLen  uint16
		expectedAvData []byte
	}{
		{
			data:           []byte{0x01, 0x00, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04},
			expectedAvID:   avpair.MsvAvNbComputerName,
			expectedAvLen:  4,
			expectedAvData: []byte{0x01, 0x02, 0x03, 0x04},
		},
		{
			data:           []byte{0x02, 0x00, 0x03, 0x00, 0x05, 0x06, 0x07},
			expectedAvID:   avpair.MsvAvNbDomainName,
			expectedAvLen:  3,
			expectedAvData: []byte{0x05, 0x06, 0x07},
		},
	}

	for _, test := range tests {
		av := avpair.AvPair{}
		_, err := av.Unmarshal(test.data)
		if err != nil {
			t.Fatalf("Unexpected error during unmarshal: %v", err)
		}

		if av.AvID != test.expectedAvID {
			t.Errorf("Expected AvID to be %x, got %x", test.expectedAvID, av.AvID)
		}

		if av.AvLen != test.expectedAvLen {
			t.Errorf("Expected AvLen to be %d, got %d", test.expectedAvLen, av.AvLen)
		}

		if !bytes.Equal(av.AvData, test.expectedAvData) {
			t.Errorf("Expected AvData to be %v, got %v", test.expectedAvData, av.AvData)
		}
	}
}

func TestAvPairUnmarshalTooShort(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{
			name: "empty data",
			data: []byte{},
		},
		{
			name: "1 byte",
			data: []byte{0x01},
		},
		{
			name: "2 bytes",
			data: []byte{0x01, 0x00},
		},
		{
			name: "3 bytes",
			data: []byte{0x01, 0x00, 0x04},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			av := avpair.AvPair{}
			_, err := av.Unmarshal(test.data)
			if err == nil {
				t.Error("Expected error for too short data but got nil")
			}
		})
	}
}
