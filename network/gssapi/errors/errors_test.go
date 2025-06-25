package errors_test

import (
	"testing"

	"github.com/TheManticoreProject/Manticore/network/gssapi/errors"
)

func TestGSSAPIErrorCodeString(t *testing.T) {
	tests := []struct {
		code     errors.GSSAPIErrorCode
		expected string
	}{
		{errors.GSS_S_BAD_MECH, "GSS_S_BAD_MECH"},
		{errors.GSS_S_BAD_NAME, "GSS_S_BAD_NAME"},
		{errors.GSS_S_BAD_NAMETYPE, "GSS_S_BAD_NAMETYPE"},
		{errors.GSS_S_BAD_BINDINGS, "GSS_S_BAD_BINDINGS"},
		{errors.GSS_S_BAD_STATUS, "GSS_S_BAD_STATUS"},
		{errors.GSS_S_BAD_MIC, "GSS_S_BAD_MIC"},
		{errors.GSS_S_NO_CRED, "GSS_S_NO_CRED"},
		{errors.GSS_S_NO_CONTEXT, "GSS_S_NO_CONTEXT"},
		{errors.GSS_S_DEFECTIVE_TOKEN, "GSS_S_DEFECTIVE_TOKEN"},
		{errors.GSS_S_DEFECTIVE_CREDENTIAL, "GSS_S_DEFECTIVE_CREDENTIAL"},
		{errors.GSS_S_CREDENTIALS_EXPIRED, "GSS_S_CREDENTIALS_EXPIRED"},
		{errors.GSS_S_CONTEXT_EXPIRED, "GSS_S_CONTEXT_EXPIRED"},
		{errors.GSS_S_FAILURE, "GSS_S_FAILURE"},
		{errors.GSS_S_BAD_QOP, "GSS_S_BAD_QOP"},
		{errors.GSS_S_UNAUTHORIZED, "GSS_S_UNAUTHORIZED"},
		{errors.GSS_S_UNAVAILABLE, "GSS_S_UNAVAILABLE"},
		{errors.GSS_S_DUPLICATE_ELEMENT, "GSS_S_DUPLICATE_ELEMENT"},
		{errors.GSS_S_NAME_NOT_MN, "GSS_S_NAME_NOT_MN"},
		{errors.GSSAPIErrorCode(999), "UNKNOWN_GSS_ERROR_CODE"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.code.String(); got != tt.expected {
				t.Errorf("GSSAPIErrorCode.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGSSAPIInformativeStatusString(t *testing.T) {
	tests := []struct {
		code     errors.GSSAPIInformativeStatus
		expected string
	}{
		{errors.GSS_S_CONTINUE_NEEDED, "GSS_S_CONTINUE_NEEDED"},
		{errors.GSS_S_DUPLICATE_TOKEN, "GSS_S_DUPLICATE_TOKEN"},
		{errors.GSS_S_OLD_TOKEN, "GSS_S_OLD_TOKEN"},
		{errors.GSS_S_UNSEQ_TOKEN, "GSS_S_UNSEQ_TOKEN"},
		{errors.GSS_S_GAP_TOKEN, "GSS_S_GAP_TOKEN"},
		{errors.GSSAPIInformativeStatus(999), "UNKNOWN_GSS_INFORMATIVE_STATUS_CODE"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.code.String(); got != tt.expected {
				t.Errorf("GSSAPIInformativeStatus.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGSSAPIErrorMessages(t *testing.T) {
	tests := []struct {
		code     errors.GSSAPIErrorCode
		expected string
	}{
		{errors.GSS_S_BAD_MECH, "Unsupported mechanism requested"},
		{errors.GSS_S_BAD_NAME, "Invalid name provided"},
		{errors.GSS_S_BAD_NAMETYPE, "Name of unsupported type provided"},
		{errors.GSS_S_BAD_BINDINGS, "Channel binding mismatch"},
		{errors.GSS_S_BAD_STATUS, "Invalid input status selector"},
		{errors.GSS_S_BAD_MIC, "Token had invalid integrity check"},
		{errors.GSS_S_NO_CRED, "No valid credentials provided"},
		{errors.GSS_S_NO_CONTEXT, "No valid security context specified"},
		{errors.GSS_S_DEFECTIVE_TOKEN, "Defective token detected"},
		{errors.GSS_S_DEFECTIVE_CREDENTIAL, "Defective credential detected"},
		{errors.GSS_S_CREDENTIALS_EXPIRED, "Expired credentials detected"},
		{errors.GSS_S_CONTEXT_EXPIRED, "Specified security context expired"},
		{errors.GSS_S_FAILURE, "Failure, unspecified at GSS-API level"},
		{errors.GSS_S_BAD_QOP, "Unsupported QOP value"},
		{errors.GSS_S_UNAUTHORIZED, "Operation unauthorized"},
		{errors.GSS_S_UNAVAILABLE, "Operation unavailable"},
		{errors.GSS_S_DUPLICATE_ELEMENT, "Duplicate credential element requested"},
		{errors.GSS_S_NAME_NOT_MN, "Name contains multi-mechanism elements"},
	}

	for _, tt := range tests {
		t.Run(tt.code.String(), func(t *testing.T) {
			if got := errors.GSSAPIErrorMessages[tt.code]; got != tt.expected {
				t.Errorf("GSSAPIErrorMessages[%v] = %v, want %v", tt.code, got, tt.expected)
			}
		})
	}
}

func TestGSSAPIInformativeStatusMessages(t *testing.T) {
	tests := []struct {
		code     errors.GSSAPIInformativeStatus
		expected string
	}{
		{errors.GSS_S_CONTINUE_NEEDED, "Continuation call to routine required"},
		{errors.GSS_S_DUPLICATE_TOKEN, "Duplicate per-message token detected"},
		{errors.GSS_S_OLD_TOKEN, "Timed-out per-message token detected"},
		{errors.GSS_S_UNSEQ_TOKEN, "Reordered (early) per-message token detected"},
		{errors.GSS_S_GAP_TOKEN, "Skipped predecessor token(s) detected"},
	}

	for _, tt := range tests {
		t.Run(tt.code.String(), func(t *testing.T) {
			if got := errors.GSSAPIInformativeStatusMessages[tt.code]; got != tt.expected {
				t.Errorf("GSSAPIInformativeStatusMessages[%v] = %v, want %v", tt.code, got, tt.expected)
			}
		})
	}
}
