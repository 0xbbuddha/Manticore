package gssapi

import (
	"errors"

	"github.com/TheManticoreProject/Manticore/network/gssapi/status"
)

// IndicateMechs() indicates the mech_types supported on local system
// Source: https://www.rfc-editor.org/rfc/pdfrfc/rfc2743.txt.pdf#page=30
func IndicateMechs() (major status.GSSAPIMajorStatus, minor status.GSSAPIMinorStatus, mechSet [][]byte, err error) {
	// TODO: Implement IndicateMechs functionality
	return status.GSS_S_FAILURE, 0, nil, errors.New("not implemented")
}

// InquireNamesForMech() indicate name types supported by mechanism
// Source: https://www.rfc-editor.org/rfc/pdfrfc/rfc2743.txt.pdf#page=30
func InquireNamesForMech() error {
	return errors.New("not implemented")
}

// InquireMechsForName() indicate mechanisms supported by name
// Source: https://www.rfc-editor.org/rfc/pdfrfc/rfc2743.txt.pdf#page=30
func InquireMechsForName() error {
	return errors.New("not implemented")
}
