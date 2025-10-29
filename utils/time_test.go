package utils_test

import (
	"testing"
	"time"

	"github.com/TheManticoreProject/Manticore/utils"
)

func TestTimeStringToTime(t *testing.T) { // Renamed test function to match the actual utility function
	tests := []struct {
		name         string
		timeString   string
		expectError  bool
		expectedTime *time.Time // Changed to pointer to time.Time
	}{
		{
			name:         "empty string",
			timeString:   "",
			expectError:  false,
			expectedTime: nil, // Will be checked against time.Now() within a delta
		},
		{
			name:         "valid RFC3339 time string",
			timeString:   "2021-01-01T12:00:00Z",
			expectError:  false,
			expectedTime: func() *time.Time { t := time.Date(2021, 1, 1, 12, 0, 0, 0, time.UTC); return &t }(),
		},
		{
			name:         "valid RFC3339 time string with offset",
			timeString:   "2023-10-27T10:30:00-07:00",
			expectError:  false,
			expectedTime: func() *time.Time { t := time.Date(2023, 10, 27, 10, 30, 0, 0, time.FixedZone("", -7*60*60)); return &t }(),
		},
		{
			name:         "invalid time string",
			timeString:   "invalid",
			expectError:  true,
			expectedTime: nil, // Expect nil time pointer on error
		},
		{
			name:         "another invalid time string format",
			timeString:   "2021/01/01 12:00:00", // Not RFC3339
			expectError:  true,
			expectedTime: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := utils.TimeStringToTime(tt.timeString) // Call the correct utility function

			if tt.expectError {
				if err == nil {
					t.Errorf("TimeStringToTime(%q) expected an error, but got none", tt.timeString)
				}
				if got != nil {
					t.Errorf("TimeStringToTime(%q) expected nil time on error, but got %v", tt.timeString, *got)
				}
			} else { // No error expected
				if err != nil {
					t.Errorf("TimeStringToTime(%q) did not expect an error, but got: %v", tt.timeString, err)
				}
				if got == nil {
					t.Fatalf("TimeStringToTime(%q) expected a time, but got nil", tt.timeString)
				}

				if tt.timeString == "" {
					// For empty string, check if the time is close to now
					// We can't compare directly with time.Now() because it changes slightly.
					// Check if it's within a small delta (e.g., 2 seconds) of the test execution time.
					now := time.Now()
					if got.Before(now.Add(-2*time.Second)) || got.After(now.Add(2*time.Second)) {
						t.Errorf("TimeStringToTime(%q) = %v, expected time close to %v", tt.timeString, *got, now)
					}
				} else {
					// For valid time string, compare directly
					if !got.Equal(*tt.expectedTime) {
						t.Errorf("TimeStringToTime(%q) = %v, want %v", tt.timeString, *got, *tt.expectedTime)
					}
				}
			}
		})
	}
}
