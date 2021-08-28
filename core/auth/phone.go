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

func (a *phoneAuthImpl) userExist(authType model.AuthType, appType model.ApplicationType, creds string, l *logs.Log) (*model.User, error) {
	return nil, nil
}

func (a *phoneAuthImpl) checkCredentials(user model.User, authType model.AuthType, appType model.ApplicationType, creds string, l *logs.Log) (*bool, error) {
	return nil, nil
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
