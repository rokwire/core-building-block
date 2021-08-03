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
	auth     *Auth
	authType string
}

func (a *samlAuthImpl) check(creds string, orgID string, appID string, params string, l *log.Log) (*model.UserAuth, error) {
	//TODO: Implement
	return nil, log.NewError(log.Unimplemented)
}

//refresh must be implemented for SAML auth
func (a *samlAuthImpl) refresh(refreshToken string, orgID string, appID string, l *log.Log) (*model.UserAuth, error) {
	//TODO: Implement
	return nil, log.NewError(log.Unimplemented)
}

func (a *samlAuthImpl) getLoginURL(orgID string, appID string, redirectUri string, l *log.Log) (string, map[string]interface{}, error) {
	return "", nil, log.NewErrorf("get login url operation invalid for auth_type=%s", a.authType)
}

//initSamlAuth initializes and registers a new SAML auth instance
func initSamlAuth(auth *Auth) (*samlAuthImpl, error) {
	saml := &samlAuthImpl{auth: auth, authType: authTypeSaml}

	err := auth.registerAuthType(saml.authType, saml)
	if err != nil {
		return nil, log.WrapErrorAction(log.ActionRegister, typeAuthType, nil, err)
	}

	return saml, nil
}
