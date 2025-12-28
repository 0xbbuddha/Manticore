package cp037_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/encoding/ascii"
	"github.com/TheManticoreProject/Manticore/encoding/ebcdic/cp037"
)

func TestCp037ToAsciiMap(t *testing.T) {
	asciiCharset := ascii.GetAsciiCharset()
	result := cp037.EbcdicCp037ToAscii(asciiCharset)
	if len(result) != len(cp037.EbcdicCp037ToAsciiMap[:]) {
		t.Fatalf("Result length mismatch, got %d expected %d", len(result), len(cp037.EbcdicCp037ToAsciiMap[:]))
	}
	for i, v := range cp037.EbcdicCp037ToAsciiMap[:] {
		if result[i] != v {
			t.Errorf("Ebcdiccp037ToAscii failed at index %d: got %v, expected %v", i, result[i], v)
		}
	}
}

func TestAsciiToCp037Map(t *testing.T) {
	asciiCharset := ascii.GetAsciiCharset()
	result := cp037.AsciiToEbcdicCp037(asciiCharset)
	if len(result) != len(cp037.AsciiToEbcdicCp037Map[:]) {
		t.Fatalf("Result length mismatch, got %d expected %d", len(result), len(cp037.AsciiToEbcdicCp037Map[:]))
	}
	for i, v := range cp037.AsciiToEbcdicCp037Map[:] {
		if result[i] != v {
			t.Errorf("Ebcdiccp037ToAscii failed at index %d: got %v, expected %v", i, result[i], v)
		}
	}
}
