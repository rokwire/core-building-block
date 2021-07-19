package auth

import log "github.com/rokmetro/logging-library/loglib"

// SAML implementation of authType
type samlAuthImpl struct {
	auth *Auth
}

func (a *samlAuthImpl) check(creds string, params string, l *log.Log) (*UserAuth, error) {
	//TODO: Implement
	return nil, log.NewError(log.Unimplemented)
}

//initSamlAuth initializes and registers a new SAML auth instance
func initSamlAuth(auth *Auth) (*samlAuthImpl, error) {
	saml := &samlAuthImpl{auth: auth}

	err := auth.registerAuthType("saml", saml)
	if err != nil {
		return nil, log.WrapActionError(log.RegisterAction, typeAuthType, nil, err)
	}

	return saml, nil
}
