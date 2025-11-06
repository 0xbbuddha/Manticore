package blob_test

import (
	"bytes"
	"testing"

	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/blob"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/headers"
)

func TestBCRYPT_DSA_PRIVATE_BLOB_MarshalUnmarshal(t *testing.T) {
	// Header specifies key length in bytes
	header := headers.BCRYPT_DSA_KEY_BLOB{
		CbKey: 2048,
		Count: [4]byte{0x11, 0x22, 0x33, 0x44},
		Seed:  [20]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19},
		Q:     [20]byte{19, 18, 17, 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0},
	}

	// Prepare input blob
	input := blob.BCRYPT_DSA_PRIVATE_BLOB{
		Modulus:   make([]byte, header.CbKey),
		Generator: make([]byte, header.CbKey),
		Public:    make([]byte, header.CbKey),
	}
	for i := 0; i < int(header.CbKey); i++ {
		input.Modulus[i] = byte(i)
		input.Generator[i] = byte(255 - (i % 256))
		input.Public[i] = byte((i * 3) % 256)
	}
	for i := 0; i < 20; i++ {
		input.PrivateExponent[i] = byte(i + 1)
	}

	// Marshal
	raw, err := input.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	expectedSize := int(header.CbKey)*3 + 20
	if len(raw) != expectedSize {
		t.Fatalf("Marshal produced wrong size, got %d, want %d", len(raw), expectedSize)
	}

	// Unmarshal
	var got blob.BCRYPT_DSA_PRIVATE_BLOB
	consumed, err := got.Unmarshal(header, raw)
	if err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if consumed != len(raw) {
		t.Fatalf("Unmarshal consumed wrong size, got %d, want %d", consumed, len(raw))
	}
	if !bytes.Equal(got.Modulus, input.Modulus) {
		t.Errorf("Modulus mismatch after unmarshal")
	}
	if !bytes.Equal(got.Generator, input.Generator) {
		t.Errorf("Generator mismatch after unmarshal")
	}
	if !bytes.Equal(got.Public, input.Public) {
		t.Errorf("Public mismatch after unmarshal")
	}
	if got.PrivateExponent != input.PrivateExponent {
		t.Errorf("PrivateExponent mismatch after unmarshal")
	}
}

func TestBCRYPT_DSA_PRIVATE_BLOB_Unmarshal_ShortInput(t *testing.T) {
	header := headers.BCRYPT_DSA_KEY_BLOB{CbKey: 128}
	var b blob.BCRYPT_DSA_PRIVATE_BLOB
	_, err := b.Unmarshal(header, []byte{1, 2, 3})
	if err == nil {
		t.Fatalf("Expected error on short buffer, got nil")
	}
}

func TestBCRYPT_DSA_PRIVATE_BLOB_Marshal_Unmarshal_Roundtrip(t *testing.T) {
	header := headers.BCRYPT_DSA_KEY_BLOB{CbKey: 128}
	orig := blob.BCRYPT_DSA_PRIVATE_BLOB{
		Modulus:   make([]byte, header.CbKey),
		Generator: make([]byte, header.CbKey),
		Public:    make([]byte, header.CbKey),
	}
	for i := 0; i < int(header.CbKey); i++ {
		orig.Modulus[i] = byte(127 - i)
		orig.Generator[i] = byte(i % 251)
		orig.Public[i] = byte((i * 7) % 256)
	}
	for i := 0; i < 20; i++ {
		orig.PrivateExponent[i] = byte(20 - i)
	}

	raw, err := orig.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var parsed blob.BCRYPT_DSA_PRIVATE_BLOB
	n, err := parsed.Unmarshal(header, raw)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if n != len(raw) {
		t.Fatalf("Did not consume all input: %d/%d", n, len(raw))
	}
	if !bytes.Equal(parsed.Modulus, orig.Modulus) {
		t.Errorf("Modulus mismatch roundtrip")
	}
	if !bytes.Equal(parsed.Generator, orig.Generator) {
		t.Errorf("Generator mismatch roundtrip")
	}
	if !bytes.Equal(parsed.Public, orig.Public) {
		t.Errorf("Public mismatch roundtrip")
	}
	if parsed.PrivateExponent != orig.PrivateExponent {
		t.Errorf("PrivateExponent mismatch roundtrip")
	}
}
