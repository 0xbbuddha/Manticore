package ntlmv2

import (
	"bytes"
	"encoding/hex"
	"testing"
	"time"
)

// TestComputeResponse_MSNLMPSection4_2_4 validates ComputeResponse against the
// MS-NLMP §4.2.4 worked example ("NTLMv2 Authentication") which fixes every
// variable (challenges, timestamp, server TargetInfo) and publishes the
// expected NTProofStr, NT response, and LM response.
//
// Reference: MS-NLMP §4.2.4 (NTLMv2 Authentication)
func TestComputeResponse_MSNLMPSection4_2_4(t *testing.T) {
	// NTOWFv2(Password="Password", User="User", UserDomain="Domain")
	responseKeyNT, _ := hex.DecodeString("0c868a403bfd7a93a3001ef22ef02e3f")
	responseKeyLM := responseKeyNT

	serverChallenge, _ := hex.DecodeString("0123456789abcdef")
	clientChallenge, _ := hex.DecodeString("aaaaaaaaaaaaaaaa")

	// TargetInfo from §4.2.4.1.3
	serverName, _ := hex.DecodeString(
		"02000c0044006f006d00610069006e00" +
			"01000c00530065007200760065007200" +
			"00000000",
	)

	// The spec fixes the timestamp to all zeros. A zero FILETIME encodes the
	// epoch 1601-01-01 UTC, so passing that time.Time yields the same blob.
	ts := time.Date(1601, 1, 1, 0, 0, 0, 0, time.UTC)

	ctx := &NTLMv2Ctx{}
	got, err := ctx.ComputeResponse(responseKeyNT, responseKeyLM, serverChallenge, clientChallenge, ts, serverName)
	if err != nil {
		t.Fatalf("ComputeResponse returned error: %v", err)
	}

	// Expected NtChallengeResponse = NTProofStr (16) || Temp
	expectedTemp, _ := hex.DecodeString(
		"01010000" + "00000000" + // RespType + HiRespType + Reserved(6) (top 4 of 6)
			"00000000" + // Reserved(6) continued (remaining 2 bytes + 2 of timestamp) -- joined below
			"" +
			"",
	)
	_ = expectedTemp // placeholder to keep the comment grouped; we rebuild below.

	expected := mustHex(
		// NTProofStr (16 bytes)
		"68cd0ab851e51c96aabc927bebef6a1c" +
			// temp blob
			"0101000000000000" + // RespType=1, HiRespType=1, Reserved=Z(6)
			"0000000000000000" + // Timestamp (FILETIME, LE, = 0 for 1601-01-01)
			"aaaaaaaaaaaaaaaa" + // ClientChallenge
			"00000000" + // Reserved Z(4)
			"02000c0044006f006d00610069006e00" + // ServerName (TargetInfo)
			"01000c00530065007200760065007200" +
			"00000000" +
			"00000000" + // Z(4)
			// LmChallengeResponse = HMAC_MD5(...) || ClientChallenge
			"86c35097ac9cec102554764a57cccc19" +
			"aaaaaaaaaaaaaaaa",
	)

	if !bytes.Equal(got, expected) {
		t.Fatalf("ComputeResponse mismatch vs MS-NLMP §4.2.4\n got:  %s\n want: %s",
			hex.EncodeToString(got), hex.EncodeToString(expected))
	}
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
