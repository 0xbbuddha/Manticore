package uuid_v7_test

import (
	"testing"
	"time"

	"github.com/TheManticoreProject/Manticore/crypto/uuid/uuid_v7"
)

func TestUUIDv7GenerateAndFormat(t *testing.T) {
	var u uuid_v7.UUIDv7
	if err := u.Generate(); err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if u.UUID.Version != 7 {
		t.Errorf("expected version 7, got %d", u.UUID.Version)
	}
	if u.UUID.Variant != 0xA {
		t.Errorf("expected RFC4122 variant 0xA, got 0x%x", u.UUID.Variant)
	}

	text := u.String()
	var parsed uuid_v7.UUIDv7
	if err := parsed.FromString(text); err != nil {
		t.Fatalf("FromString failed: %v", err)
	}
	if parsed.String() != text {
		t.Errorf("round-trip mismatch: %s vs %s", parsed.String(), text)
	}
}

func TestUUIDv7RandomnessAndTimestamp(t *testing.T) {
	var a, b uuid_v7.UUIDv7
	if err := a.Generate(); err != nil {
		t.Fatalf("Generate a failed: %v", err)
	}
	if err := b.Generate(); err != nil {
		t.Fatalf("Generate b failed: %v", err)
	}
	if a.String() == b.String() {
		t.Errorf("unexpected equal UUIDs: %s", a.String())
	}

	now := time.Now()
	// Allow a small tolerance around current time
	if dt := now.Sub(a.GetTime()); dt > 5*time.Second || dt < -5*time.Second {
		t.Errorf("timestamp out of expected range: %v vs now %v", a.GetTime(), now)
	}
}
