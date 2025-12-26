package cp037_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/encoding/ascii"
	"github.com/TheManticoreProject/Manticore/encoding/ebcdic/cp037"
)

func TestCp037ToAsciiMap(t *testing.T) {
	result := cp037.EbcdicCp037ToAscii(ascii.AsciiCharset[:])
	if len(result) != len(cp037.EbcdicCp037ToAsciiMap[:]) {
		t.Fatalf("Result length mismatch, got %d expected %d", len(result), len(cp037.EbcdicCp037ToAsciiMap[:]))
	}
	for i, v := range cp037.EbcdicCp037ToAsciiMap[:] {
		if result[i] != v {
			t.Errorf("Ebcdiccp037ToAscii failed at index %d: got %v, expected %v", i, result[i], v)
		}
	}
}
