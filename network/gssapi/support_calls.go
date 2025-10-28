package gssapi

import (
	"errors"

	"github.com/TheManticoreProject/Manticore/network/gssapi/status"
)

// DisplayStatus() translate status codes to printable form
// Source: https://datatracker.ietf.org/doc/html/rfc2743#page-68
func DisplayStatus(statusValue int32, statusType int32, mechType []byte) (major status.GSSAPIMajorStatus, minor status.GSSAPIMinorStatus, statusStrings []string, err error) {
	// TODO: Implement DisplayStatus functionality
	return status.GSS_S_FAILURE, 0, nil, errors.New("not implemented")
}

// ReleaseBuffer() free storage of general GSS-allocated object
// Source: https://datatracker.ietf.org/doc/html/rfc2743#page-74
func ReleaseBuffer(buffer []byte) (major status.GSSAPIMajorStatus, minor status.GSSAPIMinorStatus, err error) {
	// TODO: Implement ReleaseBuffer functionality
	return status.GSS_S_FAILURE, 0, errors.New("not implemented")
}
