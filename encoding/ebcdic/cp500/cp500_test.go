package cp500_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/encoding/ascii"
	"github.com/TheManticoreProject/Manticore/encoding/ebcdic/cp500"
)

func TestCp500ToAsciiMap(t *testing.T) {
	asciiCharset := ascii.GetAsciiCharset()
	result := cp500.EbcdicCp500ToAscii(asciiCharset)
	if len(result) != len(cp500.EbcdicCp500ToAsciiMap[:]) {
		t.Fatalf("Result length mismatch, got %d expected %d", len(result), len(cp500.EbcdicCp500ToAsciiMap[:]))
	}
	for i, v := range cp500.EbcdicCp500ToAsciiMap[:] {
		if result[i] != v {
			t.Errorf("Ebcdiccp500ToAscii failed at index %d: got %v, expected %v", i, result[i], v)
		}
	}
}

func TestAsciiToCp500Map(t *testing.T) {
	asciiCharset := ascii.GetAsciiCharset()
	result := cp500.AsciiToEbcdicCp500(asciiCharset)
	if len(result) != len(cp500.AsciiToEbcdicCp500Map[:]) {
		t.Fatalf("Result length mismatch, got %d expected %d", len(result), len(cp500.AsciiToEbcdicCp500Map[:]))
	}
	for i, v := range cp500.AsciiToEbcdicCp500Map[:] {
		if result[i] != v {
			t.Errorf("Ebcdiccp500ToAscii failed at index %d: got %v, expected %v", i, result[i], v)
		}
	}
}
