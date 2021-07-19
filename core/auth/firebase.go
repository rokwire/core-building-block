package auth

import (
	log "github.com/rokmetro/logging-library/loglib"
)

// Firebase implementation of authType
type firebaseAuthImpl struct {
	auth *Auth
}

func (a *firebaseAuthImpl) check(creds string, params string, l *log.Log) (*UserAuth, error) {
	//TODO: Implement
	return nil, log.NewError(log.Unimplemented)
}

//initFirebaseAuth initializes and registers a new Firebase auth instance
func initFirebaseAuth(auth *Auth) (*firebaseAuthImpl, error) {
	firebase := &firebaseAuthImpl{auth: auth}

	err := auth.registerAuthType("firebase", firebase)
	if err != nil {
		return nil, log.WrapActionError(log.RegisterAction, typeAuthType, nil, err)
	}

	return firebase, nil
}
