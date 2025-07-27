package ntlmv1

import (
	"encoding/hex"
	"testing"
)

func TestNTLMv1HashFromPassword(t *testing.T) {
	serverChallenge := []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	tests := []struct {
		domain             string
		username           string
		password           string
		challenge          []byte
		expectedNTResponse string
		expectedLMResponse string
	}{
		{
			domain:             "WORKGROUP",
			username:           "podalirius",
			password:           "Podalirius!",
			challenge:          serverChallenge,
			expectedNTResponse: "8110779a47517b1e6bd686317bd8bc395a07a640ad9e3e70",
			expectedLMResponse: "f8ccbfc0d1eee6e3e6992565aaa23cc5cb0150e6034bcd28",
		},
	}

	for _, test := range tests {
		ntlmv1Ctx, err := NewNTLMv1CtxWithPassword(test.domain, test.username, test.password, test.challenge)
		if err != nil {
			t.Errorf("NewNTLMv1CtxWithPassword(%s, %s, %s, %s) returned error: %v", test.domain, test.username, test.password, test.challenge, err)
		}

		response, err := ntlmv1Ctx.ComputeResponse()
		if err != nil {
			t.Errorf("ntlmv1Ctx.ComputeResponse() returned error: %v", err)
		}
		ntResponse := response.GetNtChallengeResponse()
		hexNTResponse := hex.EncodeToString(ntResponse[:])
		if hexNTResponse != test.expectedNTResponse {
			t.Errorf("ntlmv1Ctx.ComputeResponse() = %s; expected %s", hexNTResponse, test.expectedNTResponse)
		}

		lmResponse := response.GetLmChallengeResponse()
		hexLMResponse := hex.EncodeToString(lmResponse[:])
		if hexLMResponse != test.expectedLMResponse {
			t.Errorf("ntlmv1Ctx.LMResponse() = %s; expected %s", hexLMResponse, test.expectedLMResponse)
		}
	}
}

// [SMB] NTLMv1-SSP Client   : 192.168.1.44
// [SMB] NTLMv1-SSP Username : THINKPAD-X61\user
// [SMB] NTLMv1-SSP Password : user
// [SMB] NTLMv1-SSP Hash     : user::THINKPAD-X61:82D6653B1699997800000000000000000000000000000000:2C84F06960FE5F2687E6D42E181F10F324A70D055A511AF7:1122334455667788
