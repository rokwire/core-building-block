package auth

import "errors"

// Phone implementation of authType
type phoneAuthImpl struct {
	auth *Auth
}

func (a *phoneAuthImpl) check(creds string) (*Claims, error) {
	//TODO: Implement
	return nil, errors.New("Unimplemented")
}

//newPhoneAuth creates a new phone auth instance
func newPhoneAuth() *phoneAuthImpl {
	return &phoneAuthImpl{}
}
