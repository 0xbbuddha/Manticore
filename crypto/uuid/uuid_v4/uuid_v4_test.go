package uuid_v4_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/crypto/uuid/uuid_v4"
)

func TestUUIDv4VersionAndVariant(t *testing.T) {
	const iterations = 100
	for i := 0; i < iterations; i++ {
		var u uuid_v4.UUIDv4
		if err := u.Generate(); err != nil {
			t.Fatalf("Generate failed at iteration %d: %v", i, err)
		}
		if u.UUID.Version != 4 {
			t.Errorf("iteration %d: expected version 4, got %d", i, u.UUID.Version)
		}
		if u.UUID.Variant != 0xA {
			t.Errorf("iteration %d: expected RFC4122 variant 0xA, got 0x%x", i, u.UUID.Variant)
		}
	}
}

func TestUUIDv4GenerateAndFormat(t *testing.T) {
	var u uuid_v4.UUIDv4
	if err := u.Generate(); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if u.UUID.Version != 4 {
		t.Errorf("expected version 4, got %d", u.UUID.Version)
	}
	if u.UUID.Variant != 0xA {
		t.Errorf("expected RFC4122 variant 0xA, got 0x%x", u.UUID.Variant)
	}

	// Round-trip parse
	text := u.String()
	var parsed uuid_v4.UUIDv4
	if err := parsed.FromString(text); err != nil {
		t.Fatalf("FromString failed: %v", err)
	}
	if parsed.String() != text {
		t.Errorf("round-trip mismatch: %s vs %s", parsed.String(), text)
	}
}

func TestUUIDv4Randomness(t *testing.T) {
	var u1, u2 uuid_v4.UUIDv4
	if err := u1.Generate(); err != nil {
		t.Fatalf("Generate u1 failed: %v", err)
	}
	if err := u2.Generate(); err != nil {
		t.Fatalf("Generate u2 failed: %v", err)
	}
	if u1.String() == u2.String() {
		t.Errorf("unexpected equal UUIDv4 values: %s", u1.String())
	}
}
