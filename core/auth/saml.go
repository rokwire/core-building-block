package auth

import "errors"

// SAML implementation of authType
type samlAuthImpl struct {
	auth *Auth
}

func (a *samlAuthImpl) check(creds string) (*Claims, error) {
	//TODO: Implement
	return nil, errors.New("Unimplemented")
}

//newSamlAuth creates a new SAML auth instance
func newSamlAuth() *samlAuthImpl {
	return &samlAuthImpl{}
}
