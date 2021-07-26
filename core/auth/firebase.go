package auth

import (
	"core-building-block/core/model"

	log "github.com/rokmetro/logging-library/loglib"
)

// Firebase implementation of authType
type firebaseAuthImpl struct {
	auth *Auth
}

func (a *firebaseAuthImpl) check(creds string, params string, l *log.Log) (*model.UserAuth, error) {
	//TODO: Implement
	return nil, log.NewError(log.Unimplemented)
}

func (a *firebaseAuthImpl) set(userAuth *model.UserAuth, orgID string, appID string) (*model.AuthCred, error) {
	return nil, log.NewError(log.Unimplemented)
}

//initFirebaseAuth initializes and registers a new Firebase auth instance
func initFirebaseAuth(auth *Auth) (*firebaseAuthImpl, error) {
	firebase := &firebaseAuthImpl{auth: auth}

	err := auth.registerAuthType("firebase", firebase)
	if err != nil {
		return nil, log.WrapActionError(log.ActionRegister, typeAuthType, nil, err)
	}

	return firebase, nil
}
