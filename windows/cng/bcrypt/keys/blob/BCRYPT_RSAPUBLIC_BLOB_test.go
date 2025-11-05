package blob_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/blob"
	"github.com/TheManticoreProject/Manticore/windows/cng/bcrypt/keys/headers"
)

func TestBCRYPT_RSAPUBLIC_BLOB_MarshalUnmarshal(t *testing.T) {
	// Prepare source blob
	blobSourceHeader := headers.BCRYPT_RSAKEY_BLOB{
		BitLength:   2048,
		CbPublicExp: 3,
		CbModulus:   256,
		CbPrime1:    0,
		CbPrime2:    0,
	}
	blobSource := &blob.BCRYPT_RSAPUBLIC_BLOB{
		PublicExponent: []byte{0x01, 0x00, 0x01},
		Modulus:        make([]byte, blobSourceHeader.CbModulus),
	}
	for i := 0; i < len(blobSource.Modulus); i++ {
		blobSource.Modulus[i] = byte(i)
	}

	// Marshal source blob
	data, err := blobSource.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if len(data) != len(blobSource.PublicExponent)+len(blobSource.Modulus) {
		t.Errorf("Marshal produced wrong size, got %d, want %d", len(data), len(blobSource.PublicExponent)+len(blobSource.Modulus))
	}

	// Unmarshal source blob
	parsed := blob.BCRYPT_RSAPUBLIC_BLOB{}
	n, err := parsed.Unmarshal(blobSourceHeader, data)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if n != len(data) {
		t.Errorf("Unmarshal consumed wrong size, got %d, want %d", n, len(data))
	}
	if !bytes.Equal(parsed.PublicExponent, blobSource.PublicExponent) {
		t.Errorf("PublicExponent mismatch: got %v, want %v", parsed.PublicExponent, blobSource.PublicExponent)
	}
	if !bytes.Equal(parsed.Modulus, blobSource.Modulus) {
		t.Errorf("Modulus mismatch: got %x, want %x", parsed.Modulus, blobSource.Modulus)
	}
}

func TestBCRYPT_RSAPUBLIC_BLOB_Unmarshal_ShortInput(t *testing.T) {
	var blob blob.BCRYPT_RSAPUBLIC_BLOB
	_, err := blob.Unmarshal(headers.BCRYPT_RSAKEY_BLOB{
		BitLength:   2048,
		CbPublicExp: 3,
		CbModulus:   256,
		CbPrime1:    0,
		CbPrime2:    0,
	}, []byte{1, 2, 3}) // too short
	if err == nil {
		t.Fatal("Expected error on short buffer, got nil")
	}
	wantError := errors.New("buffer too small for BCRYPT_RSAPUBLIC_BLOB, not enough bytes for unmarshalling modulus")
	if err.Error() != wantError.Error() {
		t.Errorf("Unexpected error for short buffer: %v, want: %v", err, wantError)
	}
}

func TestBCRYPT_RSAPUBLIC_BLOB_Marshal_Unmarshal_Roundtrip(t *testing.T) {
	header := headers.BCRYPT_RSAKEY_BLOB{
		BitLength:   1024,
		CbPublicExp: 3,
		CbModulus:   128,
		CbPrime1:    0,
		CbPrime2:    0,
	}
	exponent := []byte{1, 0, 1}
	modulus := make([]byte, 128)
	for i := 0; i < 128; i++ {
		modulus[i] = byte(127 - i)
	}
	orig := blob.BCRYPT_RSAPUBLIC_BLOB{
		PublicExponent: exponent,
		Modulus:        modulus,
	}
	raw, err := orig.Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	var parsed blob.BCRYPT_RSAPUBLIC_BLOB
	n, err := parsed.Unmarshal(header, raw)
	if err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	if n != len(raw) {
		t.Fatalf("Did not consume all input: %d/%d", n, len(raw))
	}
	if !bytes.Equal(parsed.PublicExponent, orig.PublicExponent) {
		t.Errorf("Exponent mismatch roundtrip")
	}
	if !bytes.Equal(parsed.Modulus, orig.Modulus) {
		t.Errorf("Modulus mismatch roundtrip")
	}
}
