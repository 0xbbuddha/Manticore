package errors

import "errors"

// Common errors
var (
	ErrInvalidDomainName         = errors.New("invalid domain name")
	ErrInvalidMessage            = errors.New("invalid message format")
	ErrInvalidHeader             = errors.New("invalid header format")
	ErrInvalidQuestion           = errors.New("invalid question format")
	ErrInvalidAnswer             = errors.New("invalid answer format")
	ErrInvalidAuthority          = errors.New("invalid authority format")
	ErrInvalidAdditional         = errors.New("invalid additional format")
	ErrInvalidResourceRecord     = errors.New("invalid resource record format")
	ErrInvalidResourceRecordType = errors.New("invalid resource record type")
	ErrNameTooLong               = errors.New("domain name too long")
	ErrLabelTooLong              = errors.New("label too long")
)
