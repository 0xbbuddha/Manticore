package ebcdic

import (
	"fmt"

	"github.com/TheManticoreProject/Manticore/encoding/ebcdic/cp037"
	"github.com/TheManticoreProject/Manticore/encoding/ebcdic/cp500"
)

var AvailableCodepages = []string{
	"cp037",
	"cp500",
}

var CodepageToEbcdicToAsciiMap = map[string][]uint8{
	"cp037": cp037.EbcdicCp037ToAsciiMap[:],
	"cp500": cp500.EbcdicCp500ToAsciiMap[:],
}
var CodepageToAsciiToEbcdicMap = map[string][]uint8{
	"cp037": cp037.AsciiToEbcdicCp037Map[:],
	"cp500": cp500.AsciiToEbcdicCp500Map[:],
}

func EbcdicToAscii(codepage string, b []uint8) ([]uint8, error) {
	ebcdicToAsciiMap, ok := CodepageToEbcdicToAsciiMap[codepage]
	if !ok {
		return nil, fmt.Errorf("codepage %s not found", codepage)
	}
	for i, v := range b {
		b[i] = ebcdicToAsciiMap[v]
	}
	return b, nil
}

func AsciiToEbcdic(codepage string, b []uint8) ([]uint8, error) {
	asciiToEbcdicMap, ok := CodepageToAsciiToEbcdicMap[codepage]
	if !ok {
		return nil, fmt.Errorf("codepage %s not found", codepage)
	}
	for i, v := range b {
		b[i] = asciiToEbcdicMap[v]
	}
	return b, nil
}
