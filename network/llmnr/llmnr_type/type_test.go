package llmnr_type_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/network/llmnr/llmnr_type"
)

func TestMarshalUnmarshal(t *testing.T) {
	allVals := []llmnr_type.Type{
		llmnr_type.TypeA,
		llmnr_type.TypeNS,
		llmnr_type.TypeCNAME,
		llmnr_type.TypeSOA,
		llmnr_type.TypePTR,
		llmnr_type.TypeMX,
		llmnr_type.TypeTXT,
		llmnr_type.TypeAAAA,
		llmnr_type.TypeSRV,
		llmnr_type.TypeOPT,
		llmnr_type.TypeAXFR,
		llmnr_type.TypeALL,
	}
	for _, ty := range allVals {
		marshalled, err := ty.Marshal()
		if err != nil {
			t.Fatalf("Marshal(%v) failed: %v", t, err)
		}

		var decoded llmnr_type.Type
		n, err := decoded.Unmarshal(marshalled)
		if err != nil {
			t.Fatalf("Unmarshal(%v) failed: %v", marshalled, err)
		}

		if n != 2 {
			t.Errorf("Unmarshal() read %d bytes; want 2", n)
		}

		if decoded != ty {
			t.Errorf("Unmarshal(Marshal(%v)) = %v; want %v", ty, decoded, ty)
		}
	}
}
