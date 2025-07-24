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

		ntResponse, err := ntlmv1Ctx.NTResponse()
		if err != nil {
			t.Errorf("ntlmv1Ctx.NTResponse() returned error: %v", err)
		}
		hexNTResponse := hex.EncodeToString(ntResponse)
		if hexNTResponse != test.expectedNTResponse {
			t.Errorf("ntlmv1Ctx.NTResponse() = %s; expected %s", hexNTResponse, test.expectedNTResponse)
		}

		lmResponse, err := ntlmv1Ctx.LMResponse()
		if err != nil {
			t.Errorf("ntlmv1Ctx.LMResponse() returned error: %v", err)
		}
		hexLMResponse := hex.EncodeToString(lmResponse)
		if hexLMResponse != test.expectedLMResponse {
			t.Errorf("ntlmv1Ctx.LMResponse() = %s; expected %s", hexLMResponse, test.expectedLMResponse)
		}
	}
}
