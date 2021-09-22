package auth

import (
	"core-building-block/core/model"

	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logs"
	"github.com/rokmetro/logging-library/logutils"
)

const (
	authTypeFirebase string = "firebase"
)

// Firebase implementation of authType
type firebaseAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *firebaseAuthImpl) userExist(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, l *logs.Log) (*model.Account, *model.AccountAuthType, error) {
	return nil, nil, nil
}

func (a *firebaseAuthImpl) verify(accountAuthType *model.AccountAuthType, id string, verification string, l *logs.Log) error {
	return errors.New(logutils.Unimplemented)
}
func (a *firebaseAuthImpl) checkCredentials(accountAuthType *model.AccountAuthType, creds string, appOrg model.ApplicationOrganization, l *logs.Log) (*string, map[string]interface{}, error) {
	return nil, nil, nil
}

//initFirebaseAuth initializes and registers a new Firebase auth instance
func initFirebaseAuth(auth *Auth) (*firebaseAuthImpl, error) {
	firebase := &firebaseAuthImpl{auth: auth, authType: authTypeFirebase}

	err := auth.registerAuthType(firebase.authType, firebase)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return firebase, nil
}
