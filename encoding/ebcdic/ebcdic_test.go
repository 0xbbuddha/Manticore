package ebcdic_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/encoding/ascii"
	"github.com/TheManticoreProject/Manticore/encoding/ebcdic"
)

func TestAsciiToEbcdicToAsciiInvolution(t *testing.T) {
	for _, codepage := range ebcdic.AvailableCodepages {
		asciiCharset := ascii.GetAsciiCharset()

		// Encode ASCII -> EBCDIC for this codepage
		ebcdicData, err := ebcdic.AsciiToEbcdic(codepage, asciiCharset)
		if err != nil {
			t.Fatalf("AsciiToEbcdic failed for codepage %s: %v", codepage, err)
		}

		// Decode EBCDIC -> ASCII for this codepage
		roundTrip, err := ebcdic.EbcdicToAscii(codepage, ebcdicData)
		if err != nil {
			t.Fatalf("EbcdicToAscii failed for codepage %s: %v", codepage, err)
		}

		expectedCharset := ascii.GetAsciiCharset()
		if len(roundTrip) != len(expectedCharset) {
			t.Errorf("Roundtrip length mismatch for codepage %s: got %d, want %d", codepage, len(roundTrip), len(expectedCharset))
			continue
		}

		for i := range expectedCharset {
			if roundTrip[i] != expectedCharset[i] {
				t.Errorf("Roundtrip mismatch at index %d for codepage %s: got %02x, want %02x", i, codepage, roundTrip[i], expectedCharset[i])
			}
		}
	}
}

func TestAsciiToEbcdic(t *testing.T) {
	for _, codepage := range ebcdic.AvailableCodepages {

		// Get the EBCDIC to ASCII map for this codepage
		asciiToEbcdicMap, ok := ebcdic.CodepageToAsciiToEbcdicMap[codepage]
		if !ok {
			t.Fatalf("CodepageToEbcdicToAsciiMap for codepage %s not found", codepage)
		}

		// Get a fresh copy of the ASCII charset for each codepage
		asciiCharset := ascii.GetAsciiCharset()

		// Encode ASCII -> EBCDIC for this codepage
		ebcdicData, err := ebcdic.AsciiToEbcdic(codepage, asciiCharset)
		if err != nil {
			t.Fatalf("AsciiToEbcdic failed for codepage %s: %v", codepage, err)
		}

		if len(ebcdicData) != len(asciiToEbcdicMap) {
			t.Errorf("EBCDIC length mismatch for codepage %s: got %d, want %d", codepage, len(ebcdicData), len(asciiToEbcdicMap[:]))
			continue
		}

		for i := range asciiToEbcdicMap[:] {
			if ebcdicData[i] != asciiToEbcdicMap[i] {
				t.Errorf("ASCII to EBCDIC mismatch at index %d for codepage %s: got %02x, want %02x", i, codepage, ebcdicData[i], asciiToEbcdicMap[i])
			}
		}
	}
}
