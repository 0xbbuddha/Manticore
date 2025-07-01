package gssapi

import (
	"errors"

	"github.com/TheManticoreProject/Manticore/network/gssapi/status"
)

// CompareName() compare two names for equality
// Source: https://datatracker.ietf.org/doc/html/rfc2743#page-70
func CompareName(name1 []byte, name2 []byte) (major status.GSSAPIMajorStatus, minor status.GSSAPIMinorStatus, nameEqual bool, err error) {
	// TODO: Implement CompareName functionality
	return status.GSS_S_FAILURE, 0, false, errors.New("not implemented")
}

// DisplayName() translate name to printable form
// Source: https://datatracker.ietf.org/doc/html/rfc2743#page-71
func DisplayName(name []byte) (major status.GSSAPIMajorStatus, minor status.GSSAPIMinorStatus, nameString []byte, nameType []byte, err error) {
	// TODO: Implement DisplayName functionality
	return status.GSS_S_FAILURE, 0, nil, nil, errors.New("not implemented")
}

// ImportName() convert printable name to normalized form
// Source: https://datatracker.ietf.org/doc/html/rfc2743#page-72
func ImportName(inputNameString []byte, inputNameType []byte) (major status.GSSAPIMajorStatus, minor status.GSSAPIMinorStatus, outputName []byte, err error) {
	// TODO: Implement ImportName functionality
	return status.GSS_S_FAILURE, 0, nil, errors.New("not implemented")
}

// ReleaseName() free storage of normalized-form name
// Source: https://datatracker.ietf.org/doc/html/rfc2743#page-73
func ReleaseName(name []byte) (major status.GSSAPIMajorStatus, minor status.GSSAPIMinorStatus, err error) {
	// TODO: Implement ReleaseName functionality
	return status.GSS_S_FAILURE, 0, errors.New("not implemented")
}

// CanonicalizeName() canonicalize name
// Source: https://www.rfc-editor.org/rfc/pdfrfc/rfc2743.txt.pdf#page=30
func CanonicalizeName() error {
	return errors.New("not implemented")
}

// ExportName() externalize per-mechanism name
// Source: https://www.rfc-editor.org/rfc/pdfrfc/rfc2743.txt.pdf#page=30
func ExportName() error {
	return errors.New("not implemented")
}

// DuplicateName() duplicates a name
// Source: https://www.rfc-editor.org/rfc/pdfrfc/rfc2743.txt.pdf#page=30
func DuplicateName() error {
	return errors.New("not implemented")
}
