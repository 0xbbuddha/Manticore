package status

type GSSAPIMajorStatus int32
type GSSAPIMinorStatus int32

// GSSAPI error codes
// Sources:
// https://www.rfc-editor.org/rfc/rfc4121.html#section-3.1
// https://docs.oracle.com/cd/E19455-01/806-3814/reference-7/index.html
const (
	// FATAL ERROR CODES
	GSS_S_BAD_MECH             GSSAPIMajorStatus = 1  // unsupported mechanism requested
	GSS_S_BAD_NAME             GSSAPIMajorStatus = 2  // invalid name provided
	GSS_S_BAD_NAMETYPE         GSSAPIMajorStatus = 3  // name of unsupported type provided
	GSS_S_BAD_BINDINGS         GSSAPIMajorStatus = 4  // channel binding mismatch
	GSS_S_BAD_STATUS           GSSAPIMajorStatus = 5  // invalid input status selector
	GSS_S_BAD_SIG              GSSAPIMajorStatus = 6  // token had invalid integrity check
	GSS_S_BAD_MIC              GSSAPIMajorStatus = 6  // preferred alias for GSS_S_BAD_SIG
	GSS_S_NO_CRED              GSSAPIMajorStatus = 7  // no valid credentials provided
	GSS_S_NO_CONTEXT           GSSAPIMajorStatus = 8  // no valid security context specified
	GSS_S_DEFECTIVE_TOKEN      GSSAPIMajorStatus = 9  // defective token detected
	GSS_S_DEFECTIVE_CREDENTIAL GSSAPIMajorStatus = 10 // defective credential detected
	GSS_S_CREDENTIALS_EXPIRED  GSSAPIMajorStatus = 11 // expired credentials detected
	GSS_S_CONTEXT_EXPIRED      GSSAPIMajorStatus = 12 // specified security context expired
	GSS_S_FAILURE              GSSAPIMajorStatus = 13 // failure, unspecified at GSS-API level
	GSS_S_BAD_QOP              GSSAPIMajorStatus = 14 // unsupported QOP value
	GSS_S_UNAUTHORIZED         GSSAPIMajorStatus = 15 // operation unauthorized
	GSS_S_UNAVAILABLE          GSSAPIMajorStatus = 16 // operation unavailable
	GSS_S_DUPLICATE_ELEMENT    GSSAPIMajorStatus = 17 // duplicate credential element requested
	GSS_S_NAME_NOT_MN          GSSAPIMajorStatus = 18 // name contains multi-mechanism elements
)

const (
	// INFORMATORY STATUS CODES
	GSS_S_CONTINUE_NEEDED GSSAPIMinorStatus = 0 // continuation call to routine required, Returned only by gss_init_sec_context() or gss_accept_sec_context(). The routine must be called again to complete its function
	GSS_S_DUPLICATE_TOKEN GSSAPIMinorStatus = 1 // duplicate per-message token detected
	GSS_S_OLD_TOKEN       GSSAPIMinorStatus = 2 // timed-out per-message token detected
	GSS_S_UNSEQ_TOKEN     GSSAPIMinorStatus = 3 // reordered (early) per-message token detected
	GSS_S_GAP_TOKEN       GSSAPIMinorStatus = 4 // skipped predecessor token(s) detected
)

var GSSAPIMajorStatusMessages = map[GSSAPIMajorStatus]string{
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

var GSSAPIMinorStatusMessages = map[GSSAPIMinorStatus]string{
	// INFORMATORY STATUS CODES
	GSS_S_CONTINUE_NEEDED: "Continuation call to routine required",
	GSS_S_DUPLICATE_TOKEN: "Duplicate per-message token detected",
	GSS_S_OLD_TOKEN:       "Timed-out per-message token detected",
	GSS_S_UNSEQ_TOKEN:     "Reordered (early) per-message token detected",
	GSS_S_GAP_TOKEN:       "Skipped predecessor token(s) detected",
}

// GSSAPIMajorStatus Messages
func (code GSSAPIMajorStatus) String() string {
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
		return "UNKNOWN_GSS_MAJOR_STATUS_CODE"
	}
}

// GSSAPIMinorStatus Messages
func (code GSSAPIMinorStatus) String() string {
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
		return "UNKNOWN_GSS_MINOR_STATUS_CODE"
	}
}
