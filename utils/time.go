package utils

import "time"

// TimeStringToTime parses a time string or returns the current time if the string is empty.
//
// Parameters:
// - timeString: A string representing the time to be parsed.
//
// Returns:
// - A pointer to a time.Time object representing the parsed time or the current time if the string is empty.
// - An error if the time string is not valid.
func TimeStringToTime(timeString string) (*time.Time, error) {
	if timeString == "" {
		t := time.Now()
		return &t, nil
	} else {
		t, err := time.Parse(time.RFC3339, timeString)
		if err != nil {
			return nil, err
		}
		return &t, nil
	}
}
