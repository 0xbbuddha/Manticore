package context

import "errors"

// Source: https://www.rfc-editor.org/rfc/pdfrfc/rfc2743.txt.pdf#page=30

type GSSAPIContext struct {
}

func NewGSSAPIContext() *GSSAPIContext {
	return &GSSAPIContext{}
}

func (s *GSSAPIContext) InitSecContext() error {
	return errors.New("not implemented")
}

func (s *GSSAPIContext) AcceptSecContext() error {
	return errors.New("not implemented")
}

func (s *GSSAPIContext) DeleteSecContext() error {
	return errors.New("not implemented")
}

func (s *GSSAPIContext) ProcessContextToken() error {
	return errors.New("not implemented")
}

func (s *GSSAPIContext) ContextTime() error {
	return errors.New("not implemented")
}

func (s *GSSAPIContext) InquireSecContext() error {
	return errors.New("not implemented")
}

func (s *GSSAPIContext) WrapSizeLimit() error {
	return errors.New("not implemented")
}

func (s *GSSAPIContext) ExportSecContext() error {
	return errors.New("not implemented")
}

func (s *GSSAPIContext) ImportSecContext() error {
	return errors.New("not implemented")
}
