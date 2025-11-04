package uuid_v6_test

import (
	"bytes"
	"testing"

	"github.com/TheManticoreProject/Manticore/crypto/uuid/uuid_v6"
)

func TestUUIDv6Unmarshal(t *testing.T) {
	var src uuid_v6.UUIDv6
	src.Time = 0x01f0340619c55c02
	src.SetClockSequence(0x0cd2)
	_ = src.SetNodeID([]byte{0x02, 0x42, 0xac, 0x12, 0x00, 0x02})
	data, err := src.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var u uuid_v6.UUIDv6
	if _, err := u.Unmarshal(data); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if u.UUID.Version != 6 {
		t.Errorf("expected version 6, got %d", u.UUID.Version)
	}

	if _, err := u.Unmarshal([]byte{0x01, 0x02}); err == nil {
		t.Errorf("expected error for short input")
	}
}

func TestUUIDv6FromStringRoundTrip(t *testing.T) {
	var src uuid_v6.UUIDv6
	src.Time = 0x01f0340619c55c02
	src.SetClockSequence(0x0cd2)
	_ = src.SetNodeID([]byte{0x02, 0x42, 0xac, 0x12, 0x00, 0x02})

	text := src.String()
	var parsed uuid_v6.UUIDv6
	if err := parsed.FromString(text); err != nil {
		t.Fatalf("FromString failed: %v", err)
	}
	if parsed.String() != text {
		t.Errorf("round-trip mismatch: %s vs %s", parsed.String(), text)
	}
	if parsed.UUID.Version != 6 {
		t.Errorf("expected version 6, got %d", parsed.UUID.Version)
	}
}

func TestUUIDv6ClockSeqRoundTrip(t *testing.T) {
	var u uuid_v6.UUIDv6
	u.SetClockSequence(0x0cd2)
	data, err := u.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var v uuid_v6.UUIDv6
	_, err = v.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if v.ClockSeq != u.ClockSeq {
		t.Errorf("clock seq mismatch: got 0x%04x want 0x%04x", v.ClockSeq, u.ClockSeq)
	}
}

func TestUUIDv6TimeRoundTrip(t *testing.T) {
	var u uuid_v6.UUIDv6
	u.Time = 0x01f0340619c55c02
	data, err := u.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var v uuid_v6.UUIDv6
	_, err = v.Unmarshal(data)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if v.Time != u.Time {
		t.Errorf("time mismatch: got 0x%016x want 0x%016x", v.Time, u.Time)
	}
}

func TestUUIDv6MarshalUnmarshalPreservesTime(t *testing.T) {
	tests := []struct {
		name     string
		uuidStr  string
		timeUint uint64
		wantErr  bool
	}{
		{
			name: "Standard UUIDv6",
			// uuidStr:  "19c55c02-3406-11f0-9cd2-0242ac120002",
			timeUint: 133920597255298050,
			wantErr:  false,
		},
		{
			name: "Another UUIDv6",
			// uuidStr:  "861c3b82-3406-11f0-9cd2-0242ac120002",
			timeUint: 133920599072930690,
			wantErr:  false,
		},
		{
			name: "Another UUIDv6",
			// uuidStr:  "00000000-0000-1000-0000-000000000000",
			timeUint: 0,
			wantErr:  false,
		},
		{
			name: "Another UUIDv6",
			// uuidStr:  "00000000-0000-1000-0000-000000000000",
			timeUint: 0x0122334455667788,
			wantErr:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var u uuid_v6.UUIDv6
			u.Time = tt.timeUint

			// Verify marshaling and unmarshaling preserves the time value
			data, err := u.Marshal()
			if err != nil {
				t.Errorf("Marshal() error = %v", err)
				return
			}

			var u2 uuid_v6.UUIDv6
			_, err = u2.Unmarshal(data)
			if err != nil {
				t.Errorf("Unmarshal() error = %v", err)
				return
			}

			if u2.Time != u.Time {
				t.Errorf("Time field not preserved during marshal/unmarshal: original %#x, got %#x",
					u.Time, u2.Time)
			}

			// Also check that the string representation is preserved
			if u2.String() != u.String() {
				t.Errorf("String representation not preserved: original %s, got %s",
					u.String(), u2.String())
			}
		})
	}
}

func TestUUIDv6MarshalUnmarshalPreservesClockSeq(t *testing.T) {
	tests := []struct {
		name         string
		uuidStr      string
		wantClockSeq uint16
		wantErr      bool
	}{
		{
			name:         "Standard UUIDv6",
			wantClockSeq: 0xcd2,
			wantErr:      false,
		},
		{
			name:         "Another UUIDv6",
			wantClockSeq: 0,
			wantErr:      false,
		},
		{
			name:         "Another UUIDv6",
			wantClockSeq: 0x0123,
			wantErr:      false,
		},
		{
			name:         "Another UUIDv6",
			wantClockSeq: 0x0aaa,
			wantErr:      false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var u uuid_v6.UUIDv6
			u.ClockSeq = tt.wantClockSeq

			// Verify marshaling and unmarshaling preserves the time value
			data, err := u.Marshal()
			if err != nil {
				t.Errorf("Marshal() error = %v", err)
				return
			}

			var u2 uuid_v6.UUIDv6
			_, err = u2.Unmarshal(data)
			if err != nil {
				t.Errorf("Unmarshal() error = %v", err)
				return
			}

			if u2.ClockSeq != u.ClockSeq {
				t.Errorf("Clock sequence not preserved during marshal/unmarshal: original %#x, got %#x",
					u.ClockSeq, u2.ClockSeq)
			}
		})
	}
}

func TestUUIDv6MarshalUnmarshalPreservesNodeID(t *testing.T) {
	tests := []struct {
		name       string
		wantNodeID [6]byte
		wantErr    bool
	}{
		{
			name:       "Standard UUIDv6",
			wantNodeID: [6]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab},
			wantErr:    false,
		},
		{
			name:       "Zero NodeID",
			wantNodeID: [6]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			wantErr:    false,
		},
		{
			name:       "MAC-like NodeID",
			wantNodeID: [6]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
			wantErr:    false,
		},
		{
			name:       "Another NodeID",
			wantNodeID: [6]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab},
			wantErr:    false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var u uuid_v6.UUIDv6
			copy(u.NodeID[:], tt.wantNodeID[:])

			// Verify marshaling and unmarshaling preserves the node ID
			data, err := u.Marshal()
			if err != nil {
				t.Errorf("Marshal() error = %v", err)
				return
			}

			var u2 uuid_v6.UUIDv6
			_, err = u2.Unmarshal(data)
			if err != nil {
				t.Errorf("Unmarshal() error = %v", err)
				return
			}

			if !bytes.Equal(u2.NodeID[:], u.NodeID[:]) {
				t.Errorf("NodeID not preserved during marshal/unmarshal: original %x, got %x",
					u.NodeID, u2.NodeID)
			}
		})
	}
}
