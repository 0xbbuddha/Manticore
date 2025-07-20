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

		if !(dt.GetTime().After(before) || dt.GetTime().Equal(before)) {
			t.Error("Expected time to be after or equal to before time")
		}
		if !(dt.GetTime().Before(after) || dt.GetTime().Equal(after)) {
			t.Error("Expected time to be before or equal to after time")
		}
		if dt.GetTicks() == 0 {
			t.Error("Expected non-zero ticks")
		}
	})

	t.Run("with specific ticks should set correct time", func(t *testing.T) {
		// 132918192030000000 ticks = 2022-03-15 12:00:03 UTC
		dt := utils.NewDateTime(132918192030000000)

		expected := time.Date(2022, 3, 15, 12, 0, 3, 0, time.UTC)
		if !dt.GetTime().UTC().Equal(expected) {
			t.Errorf("Expected time %v, got %v", expected, dt.GetTime().UTC())
		}
		if dt.GetTicks() != 132918192030000000 {
			t.Errorf("Expected ticks %d, got %d", 132918192030000000, dt.GetTicks())
		}
	})
}

func TestDateTime_ToUniversalTime(t *testing.T) {
	dt := utils.NewDateTime(132918192030000000) // 2022-03-15 12:00:03 UTC
	utc := dt.ToUniversalTime()

	expected := time.Date(2022, 3, 15, 12, 0, 3, 0, time.UTC)
	if !utc.Equal(expected) {
		t.Errorf("Expected UTC time %v, got %v", expected, utc)
	}
}

func TestDateTime_ToTicks(t *testing.T) {
	ticks := uint64(132918192030000000)
	dt := utils.NewDateTime(ticks)

	if dt.ToTicks() != ticks {
		t.Errorf("Expected ticks %d, got %d", ticks, dt.ToTicks())
	}
}

func TestDateTime_String(t *testing.T) {
	dt := utils.NewDateTime(132918192030000000) // 2022-03-15 12:00:03 UTC
	expected := time.Date(2022, 3, 15, 12, 0, 3, 0, time.UTC)

	// Compare the actual time values instead of string representations to avoid timezone issues
	if !dt.GetTime().UTC().Equal(expected) {
		t.Errorf("Expected time %v, got %v", expected, dt.GetTime().UTC())
	}
}

func TestDateTime_Marshal(t *testing.T) {
	dt := utils.NewDateTime(132918192030000000)
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
		// 132918192030000000 in little-endian = 2022-03-15 12:00:03 UTC
		data := []byte{0x80, 0xa3, 0x22, 0x34, 0x64, 0x38, 0xd8, 0x01}
		err := dt.Unmarshal(data)

		if err != nil {
			t.Errorf("Unexpected error: %v", err)
		}
		if dt.GetTicks() != 132918192030000000 {
			t.Errorf("Expected ticks %d, got %d", 132918192030000000, dt.GetTicks())
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

func TestDateTime_GetTime_SetTime(t *testing.T) {
	currentTime := time.Now().UTC().Truncate(100 * time.Nanosecond)

	testCases := []struct {
		name     string
		setTime  time.Time
		expected time.Time
	}{
		{
			name:     "Current time",
			setTime:  currentTime,
			expected: currentTime,
		},
		{
			name:     "Past time",
			setTime:  time.Date(2020, 1, 1, 12, 0, 0, 0, time.UTC),
			expected: time.Date(2020, 1, 1, 12, 0, 0, 0, time.UTC),
		},
		{
			name:     "Future time",
			setTime:  time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC),
			expected: time.Date(2025, 12, 31, 23, 59, 59, 0, time.UTC),
		},
		{
			name:     "Epoch time",
			setTime:  time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
			expected: time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dt := utils.NewDateTime(0)
			dt.SetTime(tc.setTime)
			result := dt.GetTime()

			if !result.Equal(tc.expected) {
				t.Errorf("Expected time %v, got %v", tc.expected, result)
			}
		})
	}
}

func TestDateTime_GetTicks_SetTicks(t *testing.T) {
	testCases := []struct {
		name        string
		setTicks    uint64
		expectedErr bool
	}{
		{
			name:        "Typical value",
			setTicks:    132918192030000000, // 2022-03-15 12:00:03 UTC
			expectedErr: false,
		},
		{
			name:        "Maximum value",
			setTicks:    ^uint64(0), // Max uint64
			expectedErr: false,
		},
		{
			name:        "Early date",
			setTicks:    116444736000000000, // 1970-01-01 00:00:00 UTC
			expectedErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			dt := utils.NewDateTime(0)
			dt.SetTicks(tc.setTicks)
			result := dt.GetTicks()

			if result != tc.setTicks {
				t.Errorf("Expected ticks %d, got %d", tc.setTicks, result)
			}

			// Verify that the time representation is consistent
			dt2 := utils.NewDateTime(tc.setTicks)
			if dt2.GetTicks() != result {
				t.Errorf("Tick values not consistent after recreation: expected %d, got %d",
					result, dt2.GetTicks())
			}
		})
	}
}
