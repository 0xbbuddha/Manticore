package cp500_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/encoding/ascii"
	"github.com/TheManticoreProject/Manticore/encoding/ebcdic/cp500"
)

func TestCp500ToAsciiMap(t *testing.T) {
	result := cp500.EbcdicCp500ToAscii(ascii.ASCIICharset[:])
	if len(result) != len(cp500.EbcdicCp500ToAsciiMap[:]) {
		t.Fatalf("Result length mismatch, got %d expected %d", len(result), len(cp500.EbcdicCp500ToAsciiMap[:]))
	}
	for i, v := range cp500.EbcdicCp500ToAsciiMap[:] {
		if result[i] != v {
			t.Errorf("Ebcdiccp500ToAscii failed at index %d: got %v, expected %v", i, result[i], v)
		}
	}
}
