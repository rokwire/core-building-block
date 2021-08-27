package auth

import (
	"core-building-block/core/model"

	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logs"
	"github.com/rokmetro/logging-library/logutils"
)

const (
	authTypeEmail string = "email"
)

// Email implementation of authType
type emailAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *emailAuthImpl) check(creds string, orgID string, appID string, params string, l *logs.Log) (*model.UserAuth, error) {
	//TODO: Implement
	return nil, errors.New("Unimplemented")
}

//refresh is enabled for email auth, but no operation is needed
func (a *emailAuthImpl) refresh(params map[string]interface{}, orgID string, appID string, l *logs.Log) (*model.UserAuth, error) {
	return nil, nil
}

func (a *emailAuthImpl) getLoginURL(orgID string, appID string, redirectURI string, l *logs.Log) (string, map[string]interface{}, error) {
	return "", nil, errors.Newf("get login url operation invalid for auth_type=%s", a.authType)
}

//initEmailAuth initializes and registers a new email auth instance
func initEmailAuth(auth *Auth) (*emailAuthImpl, error) {
	email := &emailAuthImpl{auth: auth, authType: authTypeEmail}

	err := auth.registerAuthType(email.authType, email)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return email, nil
}
