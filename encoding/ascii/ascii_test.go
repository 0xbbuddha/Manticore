package ascii

import "testing"

func TestASCIICharset(t *testing.T) {
	for i := 0; i < 256; i++ {
		if ASCIICharset[i] != uint8(i) {
			t.Errorf("ASCIICharset[%d] = %d; expected %d", i, ASCIICharset[i], uint8(i))
		}
	}
}
