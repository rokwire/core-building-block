package auth

import (
	"core-building-block/core/model"

	log "github.com/rokmetro/logging-library/loglib"
)

const (
	authTypeSaml string = "saml"
)

// SAML implementation of authType
type samlAuthImpl struct {
	auth *Auth
}

func (a *samlAuthImpl) check(creds string, params string, l *log.Log) (*model.UserAuth, error) {
	//TODO: Implement
	return nil, log.NewError(log.Unimplemented)
}

//refresh must be implemented for SAML auth
func (a *samlAuthImpl) refresh(refreshToken string, l *log.Log) (*model.UserAuth, error) {
	//TODO: Implement
	return nil, log.NewError(log.Unimplemented)
}

//initSamlAuth initializes and registers a new SAML auth instance
func initSamlAuth(auth *Auth) (*samlAuthImpl, error) {
	saml := &samlAuthImpl{auth: auth}

	err := auth.registerAuthType(authTypeSaml, saml)
	if err != nil {
		return nil, log.WrapActionError(log.ActionRegister, typeAuthType, nil, err)
	}

	return saml, nil
}
