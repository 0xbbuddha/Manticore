package datafields_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/network/smb/smb_v10/spnego/ntlm/datafields"
)

func TestMarshalUnmarshal(t *testing.T) {
	testCases := []struct {
		name    string
		fields  datafields.DataFields
		wantErr bool
	}{
		{
			name: "Basic fields",
			fields: datafields.DataFields{
				Len:          32,
				MaxLen:       64,
				BufferOffset: 128,
			},
			wantErr: false,
		},
		{
			name: "Zero values",
			fields: datafields.DataFields{
				Len:          0,
				MaxLen:       0,
				BufferOffset: 0,
			},
			wantErr: false,
		},
		{
			name: "Max values",
			fields: datafields.DataFields{
				Len:          0xFFFF,
				MaxLen:       0xFFFF,
				BufferOffset: 0xFFFFFFFF,
			},
			wantErr: false,
		},
		{
			name: "",
			fields: datafields.DataFields{
				Len:          0xAAAA,
				MaxLen:       0xBBBB,
				BufferOffset: 0xCCCCCCCC,
			},
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test Marshal
			data, err := tc.fields.Marshal()
			if (err != nil) != tc.wantErr {
				t.Errorf("Marshal() error = %v, wantErr %v", err, tc.wantErr)
				return
			}

			if !tc.wantErr {
				// Test Unmarshal
				var unmarshaledFields datafields.DataFields
				bytesRead, err := unmarshaledFields.Unmarshal(data)
				if err != nil {
					t.Errorf("Unmarshal() error = %v", err)
					return
				}

				if bytesRead != 8 {
					t.Errorf("Unmarshal() bytesRead = %v, want 8", bytesRead)
				}

				// Compare original and unmarshaled fields
				if tc.fields.Len != unmarshaledFields.Len {
					t.Errorf("Len mismatch: got %v, want %v", unmarshaledFields.Len, tc.fields.Len)
				}
				if tc.fields.MaxLen != unmarshaledFields.MaxLen {
					t.Errorf("MaxLen mismatch: got %v, want %v", unmarshaledFields.MaxLen, tc.fields.MaxLen)
				}
				if tc.fields.BufferOffset != unmarshaledFields.BufferOffset {
					t.Errorf("BufferOffset mismatch: got %v, want %v", unmarshaledFields.BufferOffset, tc.fields.BufferOffset)
				}
			}
		})
	}
}

func TestUnmarshalInvalidData(t *testing.T) {
	testCases := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name:    "Empty data",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "Data too short",
			data:    []byte{0x01, 0x02, 0x03},
			wantErr: true,
		},
		{
			name:    "Valid length",
			data:    make([]byte, 8),
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var fields datafields.DataFields
			_, err := fields.Unmarshal(tc.data)
			if (err != nil) != tc.wantErr {
				t.Errorf("Unmarshal() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
