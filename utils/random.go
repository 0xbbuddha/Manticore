package utils

import (
	crand "crypto/rand"
	"math/big"
	mrand "math/rand"
)

// RandomString generates a random string of the specified length.
//
// Parameters:
// - length: The length of the random string to generate.
//
// Returns:
// - A string of the specified length.
func RandomString(length int) string {
	if length <= 0 {
		return ""
	}
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	b := make([]byte, length)
	rangeSize := big.NewInt(int64(len(charset)))
	for i := 0; i < length; i++ {
		n, err := crand.Int(crand.Reader, rangeSize)
		if err != nil {
			b[i] = charset[mrand.Intn(len(charset))]
			continue
		}
		b[i] = charset[n.Int64()]
	}

	return string(b)
}

// RandomInt generates a random integer between min (inclusive) and max (inclusive).
//
// Parameters:
// - min: The minimum value (inclusive).
// - max: The maximum value (inclusive).
//
// Returns:
// - A random integer within the specified range.
func RandomInt(min, max int) int {
	if min > max {
		min, max = max, min // Swap if min is greater than max
	}
	// Use int64 to avoid overflow when computing range size
	a := int64(min)
	b := int64(max)
	rangeSize := b - a + 1
	if rangeSize <= 0 {
		// Overflow or invalid range; return min as a safe fallback
		return min
	}
	r, err := crand.Int(crand.Reader, big.NewInt(rangeSize))
	if err != nil {
		// Fallback to math/rand if crypto/rand fails
		return int(a + (mrand.Int63n(rangeSize)))
	}
	return int(a + r.Int64())
}

// RandomBytes generates a random byte slice of the specified length.
//
// Parameters:
// - length: The length of the byte slice to generate.
//
// Returns:
// - A byte slice filled with random data.
func RandomBytes(length int) []byte {
	if length <= 0 {
		return []byte{}
	}
	b := make([]byte, length)
	if _, err := crand.Read(b); err != nil {
		// Fallback to non-crypto PRNG if crypto/rand fails
		for i := range b {
			b[i] = byte(mrand.Intn(256))
		}
	}
	return b
}

// RandomBool generates a random boolean value.
//
// Returns:
// - A random boolean (true or false).
func RandomBool() bool {
	var one [1]byte
	if _, err := crand.Read(one[:]); err == nil {
		return (one[0] & 1) == 0 // 50% chance for true, 50% for false
	}
	return mrand.Intn(2) == 0
}
