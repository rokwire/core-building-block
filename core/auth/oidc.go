package auth

import "errors"

// OIDC implementation of authType
type oidcAuthImpl struct {
	auth *Auth
}

func (a *oidcAuthImpl) check(creds string) (*Claims, error) {
	//TODO: Implement
	return nil, errors.New("Unimplemented")
}

//newOidcAuth creates a new OIDC auth instance
func newOidcAuth() *oidcAuthImpl {
	return &oidcAuthImpl{}
}
