package utils

import (
	"encoding/binary"
	"fmt"
	"time"
)

// DateTime represents a point in time with additional precision.
//
// Fields:
// - Time: A time.Time object representing the point in time.
// - Ticks: A uint64 value representing the number of 100-nanosecond intervals that have elapsed since 1601-01-01 00:00:00 UTC.
//
// Methods:
// - NewDateTime: Initializes a new DateTime instance based on the provided ticks or the current time if ticks is 0.
// - ToUniversalTime: Converts the DateTime instance to a time.Time object in UTC.
//
// Note:
// The Ticks field provides additional precision for representing time, which is useful for certain applications that require high-resolution timestamps.
// The Time field is a standard time.Time object that can be used with Go's time package functions.
type DateTime struct {
	time  time.Time
	ticks uint64
}

// NewDateTime initializes a new DateTime instance.
//
// Parameters:
//   - ticks: A uint64 value representing the number of 100-nanosecond intervals that have elapsed since 1601-01-01 00:00:00 UTC.
//     If ticks is 0, the function sets the current time and calculates ticks from 1601 to now.
//
// Returns:
// - A DateTime object initialized with the provided ticks or the current time if ticks is 0.
//
// Note:
// The function calculates the number of nanoseconds between 1601-01-01 and the UNIX epoch (1970-01-01) to convert ticks to a time.Time object.
// If ticks is 0, the function sets the current time and calculates the ticks from 1601 to the current time.
// Otherwise, it sets the time based on the provided ticks.
func NewDateTime(ticks uint64) DateTime {
	dt := DateTime{}

	if ticks == 0 {
		dt.SetTime(time.Now())
	} else {
		dt.SetTicks(ticks)
	}

	return dt
}

// ToUniversalTime converts the DateTime instance to a time.Time object in UTC.
//
// Returns:
// - A time.Time object representing the DateTime instance in Coordinated Universal Time (UTC).
//
// Note:
// This function ensures that the time is represented in the UTC time zone, regardless of the original time zone of the DateTime instance.
func (dt DateTime) ToUniversalTime() time.Time {
	return dt.time.UTC()
}

// SetTicks sets the number of 100-nanosecond intervals (ticks) for the DateTime instance.
//
// Parameters:
// - ticks: A uint64 value representing the number of 100-nanosecond intervals since 1601-01-01 00:00:00 UTC.
//
// Note:
// This function updates both the Ticks field and recalculates the corresponding Time field based on the provided ticks.
func (dt *DateTime) SetTicks(ticks uint64) {
	epoch1601 := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	unixEpoch := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	nanosecondsBetween1601AndEpoch := uint64(unixEpoch.UnixNano() - epoch1601.UnixNano())

	dt.ticks = ticks
	ticksInNs := uint64(ticks * 100)
	nanoSecondsFromUnixEpoch := uint64(ticksInNs - nanosecondsBetween1601AndEpoch)
	dt.time = time.Unix(0, int64(nanoSecondsFromUnixEpoch))
}

// GetTicks returns the number of 100-nanosecond intervals (ticks) stored in the DateTime instance.
//
// Returns:
// - A uint64 value representing the number of 100-nanosecond intervals since 1601-01-01 00:00:00 UTC.
func (dt *DateTime) GetTicks() uint64 {
	return dt.ticks
}

// SetTime sets the time for the DateTime instance.
//
// Parameters:
// - t: A time.Time value to set.
//
// Note:
// This function updates both the Time field and recalculates the corresponding Ticks field based on the provided time.
func (dt *DateTime) SetTime(t time.Time) {
	epoch1601 := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)
	unixEpoch := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	nanosecondsBetween1601AndEpoch := uint64(unixEpoch.UnixNano() - epoch1601.UnixNano())

	dt.time = t.Truncate(100 * time.Nanosecond)
	dt.ticks = (nanosecondsBetween1601AndEpoch + uint64(t.UnixNano())) / 100
}

// GetTime returns the time.Time value stored in the DateTime instance.
//
// Returns:
// - A time.Time value representing the stored time.
func (dt *DateTime) GetTime() time.Time {
	return dt.time
}

// ToTicks returns the number of 100-nanosecond intervals (ticks) that have elapsed since 1601-01-01 00:00:00 UTC.
//
// Returns:
// - A uint64 value representing the number of 100-nanosecond intervals (ticks) since 1601-01-01 00:00:00 UTC.
//
// Note:
// This function provides a way to retrieve the internal tick count of the DateTime instance, which is useful for binary time representations and calculations.
func (dt DateTime) ToTicks() uint64 {
	return dt.ticks
}

// String returns the string representation of the DateTime instance.
//
// Returns:
// - A string representing the DateTime instance in the default format used by the time.Time type.
//
// Note:
// This function leverages the String method of the embedded time.Time type to provide a human-readable
// representation of the DateTime instance. The format typically includes the date, time, and time zone.
func (dt DateTime) String() string {
	return dt.time.String()
}

// Marshal converts the DateTime instance to its binary representation in little-endian format.
//
// Returns:
// - A byte slice containing the binary representation of the DateTime instance in little-endian format, otherwise an error.
//
// Note:
// This function encodes the Ticks field of the DateTime instance as a 64-bit unsigned integer in little-endian format.
// The function returns a byte slice containing the binary representation of the DateTime instance in little-endian format.
func (dt DateTime) Marshal() ([]byte, error) {
	return binary.LittleEndian.AppendUint64(nil, dt.ticks), nil
}

// Unmarshal converts the binary representation of the DateTime instance to a DateTime object.
//
// Parameters:
// - data: A byte slice containing the binary representation of the DateTime instance.
//
// Returns:
// - An error if the unmarshalling fails, otherwise nil.
//
// Note:
// This function decodes the Ticks field of the DateTime instance from a 64-bit unsigned integer in little-endian format.
// The function expects the data to be a 64-bit unsigned integer in little-endian format.
func (dt *DateTime) Unmarshal(data []byte) error {
	if len(data) != 8 {
		return fmt.Errorf("invalid data length: %d", len(data))
	}
	dt.ticks = binary.LittleEndian.Uint64(data)
	return nil
}
