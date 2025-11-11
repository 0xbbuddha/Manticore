package blob

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/headers"
)

func TestBCRYPT_ECC_PUBLIC_BLOB_UnmarshalMarshal(t *testing.T) {
	// Example test for P-256 (32-byte coordinates)
	cbKey := 32
	keyHeader := headers.BCRYPT_ECC_KEY_BLOB{
		KeySize: uint32(cbKey),
	}
	x, _ := hex.DecodeString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	y, _ := hex.DecodeString("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
	if len(x) != cbKey || len(y) != cbKey {
		t.Fatal("coordinate length mismatch")
	}
	raw := append(x, y...)
	var b BCRYPT_ECC_PUBLIC_BLOB
	n, err := b.Unmarshal(keyHeader, raw)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if n != cbKey*2 {
		t.Fatalf("expected bytes read %d, got %d", cbKey*2, n)
	}
	if !bytes.Equal(b.X, x) || !bytes.Equal(b.Y, y) {
		t.Error("Unmarshal did not assign correct X, Y values")
	}

	marshalled, err := b.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if !bytes.Equal(marshalled, raw) {
		t.Error("Marshal output does not match input")
	}
}

func TestBCRYPT_ECC_PUBLIC_BLOB_Equal(t *testing.T) {
	blob1 := &BCRYPT_ECC_PUBLIC_BLOB{
		X: []byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11},
		Y: []byte{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22},
	}
	blob2 := &BCRYPT_ECC_PUBLIC_BLOB{
		X: []byte{0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11},
		Y: []byte{0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22},
	}
	if !blob1.Equal(blob2) {
		t.Error("Equal should return true for identical blobs")
	}
	blob2.Y[2] = 0
	if blob1.Equal(blob2) {
		t.Error("Equal should return false when Y is different")
	}
}
