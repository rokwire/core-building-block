package auth

import (
	"core-building-block/core/model"

	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logs"
	"github.com/rokmetro/logging-library/logutils"
)

const (
	authTypeUsername string = "username"
)

// Username implementation of authType
type usernameAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *usernameAuthImpl) check(creds string, orgID string, appID string, params string, l *logs.Log) (*model.UserAuth, error) {
	//TODO: Implement
	return nil, errors.New("Unimplemented")
}

//refresh is enabled for username auth, but no operation is needed
func (a *usernameAuthImpl) refresh(params map[string]interface{}, orgID string, appID string, l *logs.Log) (*model.UserAuth, error) {
	return nil, nil
}

func (a *usernameAuthImpl) getLoginURL(orgID string, appID string, redirectURI string, l *logs.Log) (string, map[string]interface{}, error) {
	return "", nil, errors.Newf("get login url operation invalid for auth_type=%s", a.authType)
}

//initUsernameAuth initializes and registers a new username auth instance
func initUsernameAuth(auth *Auth) (*usernameAuthImpl, error) {
	username := &usernameAuthImpl{auth: auth, authType: authTypeUsername}

	err := auth.registerAuthType(username.authType, username)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return username, nil
}
