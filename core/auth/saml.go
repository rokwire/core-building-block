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

//initSamlAuth initializes and registers a new SAML auth instance
func initSamlAuth(auth *Auth) (*samlAuthImpl, error) {
	saml := &samlAuthImpl{auth: auth}

	err := auth.registerAuthType("saml", saml)
	if err != nil {
		return nil, err
	}

	return saml, nil
}
