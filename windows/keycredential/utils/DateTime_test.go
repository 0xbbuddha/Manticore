package utils_test

import (
	"testing"
	"time"

	"github.com/TheManticoreProject/Manticore/windows/keycredential/utils"
)

func TestNewDateTime(t *testing.T) {
	t.Run("with zero ticks should set current time", func(t *testing.T) {
		before := time.Now()
		dt := utils.NewDateTime(0)
		after := time.Now()

		if !(dt.Time.After(before) || dt.Time.Equal(before)) {
			t.Error("Expected time to be after or equal to before time")
		}
		if !(dt.Time.Before(after) || dt.Time.Equal(after)) {
			t.Error("Expected time to be before or equal to after time")
		}
		if dt.Ticks == 0 {
			t.Error("Expected non-zero ticks")
		}
	})

	t.Run("with specific ticks should set correct time", func(t *testing.T) {
		// 132901332030000000 ticks = 2022-03-15 12:00:03 UTC
		dt := utils.NewDateTime(132901332030000000)

		expected := time.Date(2022, 3, 15, 12, 0, 3, 0, time.UTC)
		if !dt.Time.UTC().Equal(expected) {
			t.Errorf("Expected time %v, got %v", expected, dt.Time.UTC())
		}
		if dt.Ticks != 132901332030000000 {
			t.Errorf("Expected ticks %d, got %d", 132901332030000000, dt.Ticks)
		}
	})
}

func TestDateTime_ToUniversalTime(t *testing.T) {
	dt := utils.NewDateTime(132901332030000000) // 2022-03-15 12:00:03 UTC
	utc := dt.ToUniversalTime()

	expected := time.Date(2022, 3, 15, 12, 0, 3, 0, time.UTC)
	if !utc.Equal(expected) {
		t.Errorf("Expected UTC time %v, got %v", expected, utc)
	}
}

func TestDateTime_ToTicks(t *testing.T) {
	ticks := uint64(132901332030000000)
	dt := utils.NewDateTime(ticks)

	if dt.ToTicks() != ticks {
		t.Errorf("Expected ticks %d, got %d", ticks, dt.ToTicks())
	}
}

func TestDateTime_String(t *testing.T) {
	dt := utils.NewDateTime(132901332030000000) // 2022-03-15 12:00:03 UTC
	expected := time.Date(2022, 3, 15, 12, 0, 3, 0, time.UTC).String()

	if dt.String() != expected {
		t.Errorf("Expected string %s, got %s", expected, dt.String())
	}
}

func TestDateTime_Marshal(t *testing.T) {
	dt := utils.NewDateTime(132901332030000000)
	data, err := dt.Marshal()

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}
	if len(data) != 8 { // Should be 8 bytes for uint64
		t.Errorf("Expected data length 8, got %d", len(data))
	}
}

func TestDateTime_Unmarshal(t *testing.T) {
	t.Run("valid data", func(t *testing.T) {
		dt := &utils.DateTime{}
		data := []byte{0x30, 0x75, 0x20, 0xB6, 0xFD, 0x95, 0xD5, 0x01} // 132901332030000000 in little-endian

		err := dt.Unmarshal(data)

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if dt.Ticks != 132901332030000000 {
			t.Errorf("Expected ticks %d, got %d", 132901332030000000, dt.Ticks)
		}
	})

	t.Run("invalid data length", func(t *testing.T) {
		dt := &utils.DateTime{}
		data := []byte{0x30, 0x75, 0x20} // Too short

		err := dt.Unmarshal(data)

		if err == nil {
			t.Error("Expected error, got nil")
		}
		if err.Error() != "invalid data length: 3" {
			t.Errorf("Expected error message 'invalid data length: 3', got '%s'", err.Error())
		}
	})
}
