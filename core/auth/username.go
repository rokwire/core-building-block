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

func (a *usernameAuthImpl) userExist(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, l *logs.Log) (*model.Account, *model.AccountAuthType, error) {
	return nil, nil, nil
}

func (a *usernameAuthImpl) verify(id string, verification string, appID string, orgID string, l *logs.Log) error {
	return errors.New(logutils.Unimplemented)
}

func (a *usernameAuthImpl) checkCredentials(userAuthType *model.AccountAuthType, creds string, appOrg model.ApplicationOrganization, l *logs.Log) (*model.AuthCreds, *bool, error) {
	return nil, nil, nil
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
