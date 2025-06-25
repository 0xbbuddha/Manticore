package errors

type GSSAPIErrorCode int32
type GSSAPIInformativeStatus int32

// GSSAPI error codes
// Sources:
// https://www.rfc-editor.org/rfc/rfc4121.html#section-3.1
// https://docs.oracle.com/cd/E19455-01/806-3814/reference-7/index.html
const (
	// FATAL ERROR CODES
	GSS_S_BAD_MECH             GSSAPIErrorCode = 1  // unsupported mechanism requested
	GSS_S_BAD_NAME             GSSAPIErrorCode = 2  // invalid name provided
	GSS_S_BAD_NAMETYPE         GSSAPIErrorCode = 3  // name of unsupported type provided
	GSS_S_BAD_BINDINGS         GSSAPIErrorCode = 4  // channel binding mismatch
	GSS_S_BAD_STATUS           GSSAPIErrorCode = 5  // invalid input status selector
	GSS_S_BAD_SIG              GSSAPIErrorCode = 6  // token had invalid integrity check
	GSS_S_BAD_MIC              GSSAPIErrorCode = 6  // preferred alias for GSS_S_BAD_SIG
	GSS_S_NO_CRED              GSSAPIErrorCode = 7  // no valid credentials provided
	GSS_S_NO_CONTEXT           GSSAPIErrorCode = 8  // no valid security context specified
	GSS_S_DEFECTIVE_TOKEN      GSSAPIErrorCode = 9  // defective token detected
	GSS_S_DEFECTIVE_CREDENTIAL GSSAPIErrorCode = 10 // defective credential detected
	GSS_S_CREDENTIALS_EXPIRED  GSSAPIErrorCode = 11 // expired credentials detected
	GSS_S_CONTEXT_EXPIRED      GSSAPIErrorCode = 12 // specified security context expired
	GSS_S_FAILURE              GSSAPIErrorCode = 13 // failure, unspecified at GSS-API level
	GSS_S_BAD_QOP              GSSAPIErrorCode = 14 // unsupported QOP value
	GSS_S_UNAUTHORIZED         GSSAPIErrorCode = 15 // operation unauthorized
	GSS_S_UNAVAILABLE          GSSAPIErrorCode = 16 // operation unavailable
	GSS_S_DUPLICATE_ELEMENT    GSSAPIErrorCode = 17 // duplicate credential element requested
	GSS_S_NAME_NOT_MN          GSSAPIErrorCode = 18 // name contains multi-mechanism elements

	// INFORMATORY STATUS CODES
	GSS_S_CONTINUE_NEEDED GSSAPIInformativeStatus = 0 // continuation call to routine required, Returned only by gss_init_sec_context() or gss_accept_sec_context(). The routine must be called again to complete its function
	GSS_S_DUPLICATE_TOKEN GSSAPIInformativeStatus = 1 // duplicate per-message token detected
	GSS_S_OLD_TOKEN       GSSAPIInformativeStatus = 2 // timed-out per-message token detected
	GSS_S_UNSEQ_TOKEN     GSSAPIInformativeStatus = 3 // reordered (early) per-message token detected
	GSS_S_GAP_TOKEN       GSSAPIInformativeStatus = 4 // skipped predecessor token(s) detected
)

var GSSAPIErrorMessages = map[GSSAPIErrorCode]string{
	// FATAL ERROR CODES
	GSS_S_BAD_MECH:             "Unsupported mechanism requested",
	GSS_S_BAD_NAME:             "Invalid name provided",
	GSS_S_BAD_NAMETYPE:         "Name of unsupported type provided",
	GSS_S_BAD_BINDINGS:         "Channel binding mismatch",
	GSS_S_BAD_STATUS:           "Invalid input status selector",
	GSS_S_BAD_MIC:              "Token had invalid integrity check",
	GSS_S_NO_CRED:              "No valid credentials provided",
	GSS_S_NO_CONTEXT:           "No valid security context specified",
	GSS_S_DEFECTIVE_TOKEN:      "Defective token detected",
	GSS_S_DEFECTIVE_CREDENTIAL: "Defective credential detected",
	GSS_S_CREDENTIALS_EXPIRED:  "Expired credentials detected",
	GSS_S_CONTEXT_EXPIRED:      "Specified security context expired",
	GSS_S_FAILURE:              "Failure, unspecified at GSS-API level",
	GSS_S_BAD_QOP:              "Unsupported QOP value",
	GSS_S_UNAUTHORIZED:         "Operation unauthorized",
	GSS_S_UNAVAILABLE:          "Operation unavailable",
	GSS_S_DUPLICATE_ELEMENT:    "Duplicate credential element requested",
	GSS_S_NAME_NOT_MN:          "Name contains multi-mechanism elements",
}

var GSSAPIInformativeStatusMessages = map[GSSAPIInformativeStatus]string{
	// INFORMATORY STATUS CODES
	GSS_S_CONTINUE_NEEDED: "Continuation call to routine required",
	GSS_S_DUPLICATE_TOKEN: "Duplicate per-message token detected",
	GSS_S_OLD_TOKEN:       "Timed-out per-message token detected",
	GSS_S_UNSEQ_TOKEN:     "Reordered (early) per-message token detected",
	GSS_S_GAP_TOKEN:       "Skipped predecessor token(s) detected",
}

// GSSAPIErrorCode Messages
func (code GSSAPIErrorCode) String() string {
	switch code {
	case GSS_S_BAD_MECH:
		return "GSS_S_BAD_MECH"
	case GSS_S_BAD_NAME:
		return "GSS_S_BAD_NAME"
	case GSS_S_BAD_NAMETYPE:
		return "GSS_S_BAD_NAMETYPE"
	case GSS_S_BAD_BINDINGS:
		return "GSS_S_BAD_BINDINGS"
	case GSS_S_BAD_STATUS:
		return "GSS_S_BAD_STATUS"
	case GSS_S_BAD_MIC:
		return "GSS_S_BAD_MIC"
	case GSS_S_NO_CRED:
		return "GSS_S_NO_CRED"
	case GSS_S_NO_CONTEXT:
		return "GSS_S_NO_CONTEXT"
	case GSS_S_DEFECTIVE_TOKEN:
		return "GSS_S_DEFECTIVE_TOKEN"
	case GSS_S_DEFECTIVE_CREDENTIAL:
		return "GSS_S_DEFECTIVE_CREDENTIAL"
	case GSS_S_CREDENTIALS_EXPIRED:
		return "GSS_S_CREDENTIALS_EXPIRED"
	case GSS_S_CONTEXT_EXPIRED:
		return "GSS_S_CONTEXT_EXPIRED"
	case GSS_S_FAILURE:
		return "GSS_S_FAILURE"
	case GSS_S_BAD_QOP:
		return "GSS_S_BAD_QOP"
	case GSS_S_UNAUTHORIZED:
		return "GSS_S_UNAUTHORIZED"
	case GSS_S_UNAVAILABLE:
		return "GSS_S_UNAVAILABLE"
	case GSS_S_DUPLICATE_ELEMENT:
		return "GSS_S_DUPLICATE_ELEMENT"
	case GSS_S_NAME_NOT_MN:
		return "GSS_S_NAME_NOT_MN"
	default:
		return "UNKNOWN_GSS_ERROR_CODE"
	}
}

// GSSAPIInformativeStatus Messages
func (code GSSAPIInformativeStatus) String() string {
	switch code {
	case GSS_S_CONTINUE_NEEDED:
		return "GSS_S_CONTINUE_NEEDED"
	case GSS_S_DUPLICATE_TOKEN:
		return "GSS_S_DUPLICATE_TOKEN"
	case GSS_S_OLD_TOKEN:
		return "GSS_S_OLD_TOKEN"
	case GSS_S_UNSEQ_TOKEN:
		return "GSS_S_UNSEQ_TOKEN"
	case GSS_S_GAP_TOKEN:
		return "GSS_S_GAP_TOKEN"
	default:
		return "UNKNOWN_GSS_INFORMATIVE_STATUS_CODE"
	}
}
