package auth

import (
	"core-building-block/core/model"

	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logs"
	"github.com/rokmetro/logging-library/logutils"
)

const (
	authTypePhone string = "phone"
)

// Phone implementation of authType
type phoneAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *phoneAuthImpl) userExist(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, l *logs.Log) (*model.Account, *model.AccountAuthType, error) {
	return nil, nil, nil
}

func (a *phoneAuthImpl) verify(accountAuthType *model.AccountAuthType, id string, verification string, l *logs.Log) error {
	return errors.New(logutils.Unimplemented)
}
func (a *phoneAuthImpl) checkCredentials(accountAuthType *model.AccountAuthType, creds string, appOrg model.ApplicationOrganization, l *logs.Log) (*string, map[string]interface{}, error) {
	return nil, nil, nil
}

//initPhoneAuth initializes and registers a new phone auth instance
func initPhoneAuth(auth *Auth) (*phoneAuthImpl, error) {
	phone := &phoneAuthImpl{auth: auth, authType: authTypePhone}

	err := auth.registerAuthType(phone.authType, phone)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return phone, nil
}
