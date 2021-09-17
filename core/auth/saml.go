package auth

import (
	"core-building-block/core/model"

	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logs"
	"github.com/rokmetro/logging-library/logutils"
)

const (
	//AuthTypeSaml saml auth type
	AuthTypeSaml string = "saml"
)

// SAML implementation of authType
type samlAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *samlAuthImpl) externalLogin(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, l *logs.Log) (*model.ExternalSystemUser, interface{}, error) {
	return nil, nil, nil
}

func (a *samlAuthImpl) userExist(externalUserIdentifier string, authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, l *logs.Log) (*model.Account, error) {
	return nil, nil
}

func (a *samlAuthImpl) getLoginURL(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, redirectURI string, l *logs.Log) (string, map[string]interface{}, error) {
	return "", nil, errors.Newf("get login url operation invalid for auth_type=%s", a.authType)
}

//initSamlAuth initializes and registers a new SAML auth instance
func initSamlAuth(auth *Auth) (*samlAuthImpl, error) {
	saml := &samlAuthImpl{auth: auth, authType: AuthTypeSaml}

	err := auth.registerExternalAuthType(saml.authType, saml)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return saml, nil
}
