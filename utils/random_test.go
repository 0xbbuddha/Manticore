package utils_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/TheManticoreProject/Manticore/utils"
)

func TestRandomString(t *testing.T) {
	t.Run("negative length", func(t *testing.T) {
		s := utils.RandomString(-5)
		if s != "" {
			t.Errorf("RandomString(-5) returned %q, expected empty string", s)
		}
	})
	t.Run("length 0", func(t *testing.T) {
		s := utils.RandomString(0)
		if len(s) != 0 {
			t.Errorf("RandomString(0) returned string of length %d, expected 0", len(s))
		}
		if s != "" {
			t.Errorf("RandomString(0) returned %q, expected empty string", s)
		}
	})

	t.Run("positive length", func(t *testing.T) {
		length := 10
		s := utils.RandomString(length)
		if len(s) != length {
			t.Errorf("RandomString(%d) returned string of length %d, expected %d", length, len(s), length)
		}

		// Check if characters are from the expected charset
		charset := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		for i, r := range s {
			if !strings.ContainsRune(charset, r) {
				t.Errorf("RandomString(%d) at index %d returned unexpected character %q", length, i, r)
			}
		}
	})

	t.Run("large length", func(t *testing.T) {
		length := 1000
		s := utils.RandomString(length)
		if len(s) != length {
			t.Errorf("RandomString(%d) returned string of length %d, expected %d", length, len(s), length)
		}
	})

	t.Run("multiple calls produce different strings", func(t *testing.T) {
		s1 := utils.RandomString(10)
		s2 := utils.RandomString(10)
		// While not guaranteed, it's highly probable they are different
		if s1 == s2 {
			t.Errorf("RandomString(10) called twice returned identical strings: %q", s1)
		}
	})
}

func TestRandomInt(t *testing.T) {
	t.Run("min less than max", func(t *testing.T) {
		min, max := 1, 10
		for i := 0; i < 100; i++ { // Run multiple times to increase confidence
			val := utils.RandomInt(min, max)
			if !(val >= min && val <= max) {
				t.Errorf("RandomInt(%d, %d) returned %d, which is out of range [%d, %d]", min, max, val, min, max)
			}
		}
	})

	t.Run("min equals max", func(t *testing.T) {
		min, max := 5, 5
		for i := 0; i < 100; i++ {
			val := utils.RandomInt(min, max)
			if val != min {
				t.Errorf("RandomInt(%d, %d) returned %d, expected %d", min, max, val, min)
			}
		}
	})

	t.Run("min greater than max (should swap)", func(t *testing.T) {
		min, max := 10, 1 // Function should swap these to 1, 10
		for i := 0; i < 100; i++ {
			val := utils.RandomInt(min, max)
			if !(val >= 1 && val <= 10) {
				t.Errorf("RandomInt(%d, %d) returned %d, which is out of range [1, 10] (after implicit swap)", min, max, val)
			}
		}
	})

	t.Run("negative range", func(t *testing.T) {
		min, max := -10, -1
		for i := 0; i < 100; i++ {
			val := utils.RandomInt(min, max)
			if !(val >= min && val <= max) {
				t.Errorf("RandomInt(%d, %d) returned %d, which is out of range [%d, %d]", min, max, val, min, max)
			}
		}
	})

	t.Run("mixed positive and negative range", func(t *testing.T) {
		min, max := -5, 5
		for i := 0; i < 100; i++ {
			val := utils.RandomInt(min, max)
			if !(val >= min && val <= max) {
				t.Errorf("RandomInt(%d, %d) returned %d, which is out of range [%d, %d]", min, max, val, min, max)
			}
		}
	})
}

func TestRandomBytes(t *testing.T) {
	t.Run("negative length", func(t *testing.T) {
		b := utils.RandomBytes(-1)
		if len(b) != 0 {
			t.Errorf("RandomBytes(-1) returned slice of length %d, expected 0", len(b))
		}
	})
	t.Run("length 0", func(t *testing.T) {
		b := utils.RandomBytes(0)
		if len(b) != 0 {
			t.Errorf("RandomBytes(0) returned slice of length %d, expected 0", len(b))
		}
	})

	t.Run("positive length", func(t *testing.T) {
		length := 16
		b := utils.RandomBytes(length)
		if len(b) != length {
			t.Errorf("RandomBytes(%d) returned slice of length %d, expected %d", length, len(b), length)
		}
		// Check that not all bytes are zero (highly improbable for random bytes)
		allZero := true
		for _, val := range b {
			if val != 0 {
				allZero = false
				break
			}
		}
		if allZero {
			t.Errorf("RandomBytes generated all zero bytes for length %d", length)
		}
	})

	t.Run("large length", func(t *testing.T) {
		length := 1024
		b := utils.RandomBytes(length)
		if len(b) != length {
			t.Errorf("RandomBytes(%d) returned slice of length %d, expected %d", length, len(b), length)
		}
	})

	t.Run("multiple calls produce different bytes", func(t *testing.T) {
		b1 := utils.RandomBytes(16)
		b2 := utils.RandomBytes(16)
		// While not guaranteed, it's highly probable they are different
		if bytes.Equal(b1, b2) {
			t.Errorf("RandomBytes(16) called twice returned identical byte slices")
		}
	})
}

func TestRandomBool(t *testing.T) {
	t.Run("can return both true and false over many calls", func(t *testing.T) {
		const iterations = 1000
		foundTrue := false
		foundFalse := false

		for i := 0; i < iterations; i++ {
			if utils.RandomBool() {
				foundTrue = true
			} else {
				foundFalse = true
			}
			if foundTrue && foundFalse {
				break // Optimization: stop early if both found
			}
		}
		if !foundTrue {
			t.Errorf("RandomBool did not return true after %d iterations", iterations)
		}
		if !foundFalse {
			t.Errorf("RandomBool did not return false after %d iterations", iterations)
		}
	})
}
