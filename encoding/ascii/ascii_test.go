package ascii

import "testing"

func TestASCIICharset(t *testing.T) {
	for i := 0; i < 256; i++ {
		if AsciiCharset[i] != uint8(i) {
			t.Errorf("AsciiCharset[%d] = %d; expected %d", i, AsciiCharset[i], uint8(i))
		}
	}
}
