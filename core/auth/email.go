package auth

import (
	"errors"
)

// Email implementation of authType
type emailAuthImpl struct {
	auth *Auth
}

func (a *emailAuthImpl) check(creds string) (*Claims, error) {
	//TODO: Implement
	return nil, errors.New("Unimplemented")
}

//newEmailAuth creates a new email auth instance
func newEmailAuth() *emailAuthImpl {
	return &emailAuthImpl{}
}
