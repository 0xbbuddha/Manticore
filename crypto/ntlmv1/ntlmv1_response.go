package ntlmv1

type NTLMv1Response struct {
	ServerChallenge     [8]byte  // 8-byte challenge from server
	LmChallengeResponse [24]byte // 24-byte LM challenge response
	NtChallengeResponse [24]byte // 24-byte NT challenge response
}

func NewNTLMv1Response(serverChallenge [8]byte, lmChallengeResponse [24]byte, ntChallengeResponse [24]byte) *NTLMv1Response {
	return &NTLMv1Response{
		ServerChallenge:     serverChallenge,
		LmChallengeResponse: lmChallengeResponse,
		NtChallengeResponse: ntChallengeResponse,
	}
}

// GetServerChallenge returns the server challenge
func (r *NTLMv1Response) GetServerChallenge() [8]byte {
	return r.ServerChallenge
}

// SetServerChallenge sets the server challenge
func (r *NTLMv1Response) SetServerChallenge(challenge [8]byte) {
	r.ServerChallenge = challenge
}

// GetLmChallengeResponse returns the LM challenge response
func (r *NTLMv1Response) GetLmChallengeResponse() [24]byte {
	return r.LmChallengeResponse
}

// SetLmChallengeResponse sets the LM challenge response
func (r *NTLMv1Response) SetLmChallengeResponse(response [24]byte) {
	r.LmChallengeResponse = response
}

// GetNtChallengeResponse returns the NT challenge response
func (r *NTLMv1Response) GetNtChallengeResponse() [24]byte {
	return r.NtChallengeResponse
}

// SetNtChallengeResponse sets the NT challenge response
func (r *NTLMv1Response) SetNtChallengeResponse(response [24]byte) {
	r.NtChallengeResponse = response
}

// Equal compares two NTLMv1Response objects for equality
func (r *NTLMv1Response) Equal(other *NTLMv1Response) bool {
	if other == nil {
		return false
	}
	return r.ServerChallenge == other.ServerChallenge &&
		r.LmChallengeResponse == other.LmChallengeResponse &&
		r.NtChallengeResponse == other.NtChallengeResponse
}
