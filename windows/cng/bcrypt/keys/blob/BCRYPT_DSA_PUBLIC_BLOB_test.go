package blob_test

import (
	"bytes"
	"testing"

	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/blob"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/headers"
)

func TestBCRYPT_DSA_PUBLIC_BLOB_MarshalUnmarshal(t *testing.T) {
	header := headers.BCRYPT_DSA_KEY_BLOB{CbKey: 2048}
	input := blob.BCRYPT_DSA_PUBLIC_BLOB{
		Modulus:   make([]byte, header.CbKey),
		Generator: make([]byte, header.CbKey),
		Public:    make([]byte, header.CbKey),
	}
	for i := 0; i < int(header.CbKey); i++ {
		input.Modulus[i] = byte(i)
		input.Generator[i] = byte(255 - (i % 256))
		input.Public[i] = byte((i * 5) % 256)
	}

	raw, err := input.Marshal()
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	expectedSize := int(header.CbKey) * 3
	if len(raw) != expectedSize {
		t.Fatalf("Marshal produced wrong size, got %d, want %d", len(raw), expectedSize)
	}

	var got blob.BCRYPT_DSA_PUBLIC_BLOB
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
}

func TestBCRYPT_DSA_PUBLIC_BLOB_Unmarshal_ShortInput(t *testing.T) {
	header := headers.BCRYPT_DSA_KEY_BLOB{CbKey: 128}
	var b blob.BCRYPT_DSA_PUBLIC_BLOB
	_, err := b.Unmarshal(header, []byte{1, 2, 3})
	if err == nil {
		t.Fatalf("Expected error on short buffer, got nil")
	}
}

func TestBCRYPT_DSA_PUBLIC_BLOB_Marshal_Unmarshal_Roundtrip(t *testing.T) {
	header := headers.BCRYPT_DSA_KEY_BLOB{CbKey: 128}
	orig := blob.BCRYPT_DSA_PUBLIC_BLOB{
		Modulus:   make([]byte, header.CbKey),
		Generator: make([]byte, header.CbKey),
		Public:    make([]byte, header.CbKey),
	}
	for i := 0; i < int(header.CbKey); i++ {
		orig.Modulus[i] = byte(127 - i)
		orig.Generator[i] = byte(i % 251)
		orig.Public[i] = byte((i * 7) % 256)
	}

	raw, err := orig.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var parsed blob.BCRYPT_DSA_PUBLIC_BLOB
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
}
