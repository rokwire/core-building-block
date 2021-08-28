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

func (a *emailAuthImpl) userExist(authType model.AuthType, appType model.ApplicationType, creds string, l *logs.Log) (*model.User, error) {
	appID := appType.Application.ID
	authTypeID := authType.ID
	authTypeIdentifier := "silyana@inabit.bg" //TODO get it from the creds string

	user, err := a.auth.storage.FindUser(appID, authTypeID, authTypeIdentifier)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeUser, nil, err) //TODO add args..
	}
	return user, nil
}

func (a *emailAuthImpl) checkCredentials(userAuthType model.UserAuthType, creds string, l *logs.Log) (*bool, error) {
	//TODO - get the password from the creds and check it using user auth type id - from the credentials collection

	result := true
	return &result, nil
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
