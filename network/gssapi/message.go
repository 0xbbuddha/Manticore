package gssapi

import (
	"errors"

	"github.com/TheManticoreProject/Manticore/network/gssapi/context"
	"github.com/TheManticoreProject/Manticore/network/gssapi/status"
)

// GetMIC() get message integrity code
// Source: https://datatracker.ietf.org/doc/html/rfc2743#page-63
func GetMIC(contextHandle *context.GSSAPIContext, qopReq int32, message []byte) (major status.GSSAPIMajorStatus, minor status.GSSAPIMinorStatus, perMsgToken []byte, err error) {
	// TODO: Implement GetMIC functionality
	return status.GSS_S_FAILURE, 0, nil, errors.New("not implemented")
}

// VerifyMIC() verify message integrity code
// Source: https://datatracker.ietf.org/doc/html/rfc2743#page-63
func VerifyMIC(contextHandle *context.GSSAPIContext, message []byte, perMsgToken []byte) (qopState int32, major status.GSSAPIMajorStatus, minor status.GSSAPIMinorStatus, err error) {
	// TODO: Implement VerifyMIC functionality
	return 0, status.GSS_S_FAILURE, 0, errors.New("not implemented")
}

// Unwrap() unwrap message
// Source: https://www.rfc-editor.org/rfc/pdfrfc/rfc2743.txt.pdf#page=30
func Unwrap(contextHandle *context.GSSAPIContext, inputMessage []byte) (confState bool, qopState int32, major status.GSSAPIMajorStatus, minor status.GSSAPIMinorStatus, outputMessage []byte, err error) {
	// TODO: Implement Unwrap functionality
	return false, 0, status.GSS_S_FAILURE, 0, nil, errors.New("not implemented")
}

// Wrap() wrap message
// Source: https://www.rfc-editor.org/rfc/pdfrfc/rfc2743.txt.pdf#page=30
func Wrap(contextHandle *context.GSSAPIContext, confReqFlag bool, qopReq int32, inputMessage []byte) (major status.GSSAPIMajorStatus, minor status.GSSAPIMinorStatus, confState bool, outputMessage []byte, err error) {
	// TODO: Implement Wrap functionality
	return status.GSS_S_FAILURE, 0, false, nil, errors.New("not implemented")
}
