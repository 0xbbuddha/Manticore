package blob

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/headers"
)

func TestBCRYPT_ECC_PRIVATE_BLOB_UnmarshalMarshal(t *testing.T) {
	// Example test with P-256 (32-byte coordinates)
	cbKey := 32
	keyHeader := headers.BCRYPT_ECC_KEY_BLOB{
		KeySize: uint32(cbKey),
	}
	x, _ := hex.DecodeString("11223344556677889900aabbccddeeff00112233445566778899aabbccddeeff")
	y, _ := hex.DecodeString("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100")
	d, _ := hex.DecodeString("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd00")
	if len(x) != cbKey || len(y) != cbKey || len(d) != cbKey {
		t.Fatal("coordinate/component length mismatch")
	}

	raw := append(append(append([]byte{}, x...), y...), d...)
	var b BCRYPT_ECC_PRIVATE_BLOB
	n, err := b.Unmarshal(keyHeader, raw)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if n != cbKey*3 {
		t.Fatalf("expected bytes read %d, got %d", cbKey*3, n)
	}
	if !bytes.Equal(b.X, x) || !bytes.Equal(b.Y, y) || !bytes.Equal(b.D, d) {
		t.Error("Unmarshal did not assign correct X, Y, D values")
	}

	marshalled, err := b.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if !bytes.Equal(marshalled, raw) {
		t.Error("Marshal output does not match input")
	}
}

func TestBCRYPT_ECC_PRIVATE_BLOB_Equal(t *testing.T) {
	blob1 := &BCRYPT_ECC_PRIVATE_BLOB{
		X: []byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11},
		Y: []byte{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22},
		D: []byte{0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33},
	}
	blob2 := &BCRYPT_ECC_PRIVATE_BLOB{
		X: []byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11},
		Y: []byte{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22},
		D: []byte{0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33},
	}
	if !blob1.Equal(blob2) {
		t.Error("Equal should return true for identical blobs")
	}
	blob2.D[2] = 0
	if blob1.Equal(blob2) {
		t.Error("Equal should return false when D is different")
	}
}
