package auth

import (
	"core-building-block/core/model"

	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logs"
	"github.com/rokmetro/logging-library/logutils"
)

const (
	authTypeSaml string = "saml"
)

// SAML implementation of authType
type samlAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *samlAuthImpl) check(creds string, orgID string, appID string, params string, l *logs.Log) (*model.UserAuth, error) {
	//TODO: Implement
	return nil, errors.New(logutils.Unimplemented)
}

func (a *samlAuthImpl) verify(id string, verification string, l *logs.Log) error {
	return errors.New(logutils.Unimplemented)
}

//refresh must be implemented for SAML auth
func (a *samlAuthImpl) refresh(refreshToken string, orgID string, appID string, l *logs.Log) (*model.UserAuth, error) {
	//TODO: Implement
	return nil, errors.New(logutils.Unimplemented)
}

func (a *samlAuthImpl) getLoginURL(orgID string, appID string, redirectURI string, l *logs.Log) (string, map[string]interface{}, error) {
	return "", nil, errors.Newf("get login url operation invalid for auth_type=%s", a.authType)
}

//initSamlAuth initializes and registers a new SAML auth instance
func initSamlAuth(auth *Auth) (*samlAuthImpl, error) {
	saml := &samlAuthImpl{auth: auth, authType: authTypeSaml}

	err := auth.registerAuthType(saml.authType, saml)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return saml, nil
}
