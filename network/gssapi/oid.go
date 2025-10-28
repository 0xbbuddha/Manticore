package gssapi

import (
	"errors"

	"github.com/TheManticoreProject/Manticore/network/gssapi/status"
)

// ReleaseOidSet() free storage of OID set
// Source: https://www.rfc-editor.org/rfc/pdfrfc/rfc2743.txt.pdf#page=30
func ReleaseOidSet() error {
	return errors.New("not implemented")
}

// CreateEmptyOidSet() create empty OID set
// Source: https://www.rfc-editor.org/rfc/pdfrfc/rfc2743.txt.pdf#page=30
func CreateEmptyOidSet() (major status.GSSAPIMajorStatus, minor status.GSSAPIMinorStatus, oidSet [][]byte, err error) {
	// TODO: Implement CreateEmptyOidSet functionality
	return status.GSS_S_FAILURE, 0, nil, errors.New("not implemented")
}

// AddOidSetMember() add OID to OID set
// Source: https://www.rfc-editor.org/rfc/pdfrfc/rfc2743.txt.pdf#page=30
func AddOidSetMember(memberOid []byte, oidSet [][]byte) (major status.GSSAPIMajorStatus, minor status.GSSAPIMinorStatus, err error) {
	// TODO: Implement AddOidSetMember functionality
	return status.GSS_S_FAILURE, 0, errors.New("not implemented")
}

// TestOidSetMember() test if OID is a member of OID set
// Source: https://www.rfc-editor.org/rfc/pdfrfc/rfc2743.txt.pdf#page=30
func TestOidSetMember(memberOid []byte, oidSet [][]byte) (major status.GSSAPIMajorStatus, minor status.GSSAPIMinorStatus, present bool, err error) {
	// TODO: Implement TestOidSetMember functionality
	return status.GSS_S_FAILURE, 0, false, errors.New("not implemented")
}

// OidToStr() convert OID to string
// Source: https://www.rfc-editor.org/rfc/pdfrfc/rfc2743.txt.pdf
func OidToStr() error {
	return errors.New("not implemented")
}

// StrToOid() convert string to OID
// Source: https://www.rfc-editor.org/rfc/pdfrfc/rfc2743.txt.pdf
func StrToOid() error {
	return errors.New("not implemented")
}
