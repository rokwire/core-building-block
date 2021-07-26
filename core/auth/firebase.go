package auth

import (
	"core-building-block/core/model"

	log "github.com/rokmetro/logging-library/loglib"
)

const (
	authTypeFirebase string = "firebase"
)

// Firebase implementation of authType
type firebaseAuthImpl struct {
	auth *Auth
}

func (a *firebaseAuthImpl) check(creds string, params string, l *log.Log) (*model.UserAuth, error) {
	//TODO: Implement
	return nil, log.NewError(log.Unimplemented)
}

func (a *firebaseAuthImpl) refresh(refreshToken string, l *log.Log) (*model.UserAuth, error) {
	return nil, log.NewErrorf("refresh operation invalid for auth_type=%s", authTypeFirebase)
}

//initFirebaseAuth initializes and registers a new Firebase auth instance
func initFirebaseAuth(auth *Auth) (*firebaseAuthImpl, error) {
	firebase := &firebaseAuthImpl{auth: auth}

	err := auth.registerAuthType(authTypeFirebase, firebase)
	if err != nil {
		return nil, log.WrapActionError(log.ActionRegister, typeAuthType, nil, err)
	}

	return firebase, nil
}
