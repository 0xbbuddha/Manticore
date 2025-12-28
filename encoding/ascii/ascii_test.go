package ascii

import "testing"

func TestASCIICharset(t *testing.T) {
	charset := GetAsciiCharset()
	for i := 0; i < 256; i++ {
		if charset[i] != uint8(i) {
			t.Errorf("AsciiCharset[%d] = %d; expected %d", i, charset[i], uint8(i))
		}
	}
}
