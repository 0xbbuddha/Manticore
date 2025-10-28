package status_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/network/gssapi/status"
)

func TestGSSAPIMajorStatusString(t *testing.T) {
	tests := []struct {
		code     status.GSSAPIMajorStatus
		expected string
	}{
		{status.GSS_S_BAD_MECH, "GSS_S_BAD_MECH"},
		{status.GSS_S_BAD_NAME, "GSS_S_BAD_NAME"},
		{status.GSS_S_BAD_NAMETYPE, "GSS_S_BAD_NAMETYPE"},
		{status.GSS_S_BAD_BINDINGS, "GSS_S_BAD_BINDINGS"},
		{status.GSS_S_BAD_STATUS, "GSS_S_BAD_STATUS"},
		{status.GSS_S_BAD_MIC, "GSS_S_BAD_MIC"},
		{status.GSS_S_NO_CRED, "GSS_S_NO_CRED"},
		{status.GSS_S_NO_CONTEXT, "GSS_S_NO_CONTEXT"},
		{status.GSS_S_DEFECTIVE_TOKEN, "GSS_S_DEFECTIVE_TOKEN"},
		{status.GSS_S_DEFECTIVE_CREDENTIAL, "GSS_S_DEFECTIVE_CREDENTIAL"},
		{status.GSS_S_CREDENTIALS_EXPIRED, "GSS_S_CREDENTIALS_EXPIRED"},
		{status.GSS_S_CONTEXT_EXPIRED, "GSS_S_CONTEXT_EXPIRED"},
		{status.GSS_S_FAILURE, "GSS_S_FAILURE"},
		{status.GSS_S_BAD_QOP, "GSS_S_BAD_QOP"},
		{status.GSS_S_UNAUTHORIZED, "GSS_S_UNAUTHORIZED"},
		{status.GSS_S_UNAVAILABLE, "GSS_S_UNAVAILABLE"},
		{status.GSS_S_DUPLICATE_ELEMENT, "GSS_S_DUPLICATE_ELEMENT"},
		{status.GSS_S_NAME_NOT_MN, "GSS_S_NAME_NOT_MN"},
		{status.GSSAPIMajorStatus(999), "UNKNOWN_GSS_MAJOR_STATUS_CODE"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.code.String(); got != tt.expected {
				t.Errorf("GSSAPIMajorStatus.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGSSAPIMinorStatusString(t *testing.T) {
	tests := []struct {
		code     status.GSSAPIMinorStatus
		expected string
	}{
		{status.GSS_S_CONTINUE_NEEDED, "GSS_S_CONTINUE_NEEDED"},
		{status.GSS_S_DUPLICATE_TOKEN, "GSS_S_DUPLICATE_TOKEN"},
		{status.GSS_S_OLD_TOKEN, "GSS_S_OLD_TOKEN"},
		{status.GSS_S_UNSEQ_TOKEN, "GSS_S_UNSEQ_TOKEN"},
		{status.GSS_S_GAP_TOKEN, "GSS_S_GAP_TOKEN"},
		{status.GSSAPIMinorStatus(999), "UNKNOWN_GSS_MINOR_STATUS_CODE"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.code.String(); got != tt.expected {
				t.Errorf("GSSAPIMinorStatus.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGSSAPIErrorMessages(t *testing.T) {
	tests := []struct {
		code     status.GSSAPIMajorStatus
		expected string
	}{
		{status.GSS_S_BAD_MECH, "Unsupported mechanism requested"},
		{status.GSS_S_BAD_NAME, "Invalid name provided"},
		{status.GSS_S_BAD_NAMETYPE, "Name of unsupported type provided"},
		{status.GSS_S_BAD_BINDINGS, "Channel binding mismatch"},
		{status.GSS_S_BAD_STATUS, "Invalid input status selector"},
		{status.GSS_S_BAD_MIC, "Token had invalid integrity check"},
		{status.GSS_S_NO_CRED, "No valid credentials provided"},
		{status.GSS_S_NO_CONTEXT, "No valid security context specified"},
		{status.GSS_S_DEFECTIVE_TOKEN, "Defective token detected"},
		{status.GSS_S_DEFECTIVE_CREDENTIAL, "Defective credential detected"},
		{status.GSS_S_CREDENTIALS_EXPIRED, "Expired credentials detected"},
		{status.GSS_S_CONTEXT_EXPIRED, "Specified security context expired"},
		{status.GSS_S_FAILURE, "Failure, unspecified at GSS-API level"},
		{status.GSS_S_BAD_QOP, "Unsupported QOP value"},
		{status.GSS_S_UNAUTHORIZED, "Operation unauthorized"},
		{status.GSS_S_UNAVAILABLE, "Operation unavailable"},
		{status.GSS_S_DUPLICATE_ELEMENT, "Duplicate credential element requested"},
		{status.GSS_S_NAME_NOT_MN, "Name contains multi-mechanism elements"},
	}

	for _, tt := range tests {
		t.Run(tt.code.String(), func(t *testing.T) {
			if got := status.GSSAPIMajorStatusMessages[tt.code]; got != tt.expected {
				t.Errorf("GSSAPIMajorStatusMessages[%v] = %v, want %v", tt.code, got, tt.expected)
			}
		})
	}
}

func TestGSSAPIMinorStatusMessages(t *testing.T) {
	tests := []struct {
		code     status.GSSAPIMinorStatus
		expected string
	}{
		{status.GSS_S_CONTINUE_NEEDED, "Continuation call to routine required"},
		{status.GSS_S_DUPLICATE_TOKEN, "Duplicate per-message token detected"},
		{status.GSS_S_OLD_TOKEN, "Timed-out per-message token detected"},
		{status.GSS_S_UNSEQ_TOKEN, "Reordered (early) per-message token detected"},
		{status.GSS_S_GAP_TOKEN, "Skipped predecessor token(s) detected"},
	}

	for _, tt := range tests {
		t.Run(tt.code.String(), func(t *testing.T) {
			if got := status.GSSAPIMinorStatusMessages[tt.code]; got != tt.expected {
				t.Errorf("GSSAPIMinorStatusMessages[%v] = %v, want %v", tt.code, got, tt.expected)
			}
		})
	}
}
