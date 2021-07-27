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
	auth     *Auth
	authType string
}

func (a *firebaseAuthImpl) check(creds string, orgID string, appID string, params string, l *log.Log) (*model.UserAuth, error) {
	//TODO: Implement
	return nil, log.NewError(log.Unimplemented)
}

func (a *firebaseAuthImpl) refresh(refreshToken string, orgID string, appID string, l *log.Log) (*model.UserAuth, error) {
	return nil, log.NewErrorf("refresh operation invalid for auth_type=%s", authTypeFirebase)
}

func (a *firebaseAuthImpl) getLoginUrl(orgID string, appID string, redirectUri string, l *log.Log) (string, map[string]interface{}, error) {
	return "", nil, log.NewErrorf("get login url operation invalid for auth_type=%s", a.authType)
}

//initFirebaseAuth initializes and registers a new Firebase auth instance
func initFirebaseAuth(auth *Auth) (*firebaseAuthImpl, error) {
	firebase := &firebaseAuthImpl{auth: auth, authType: authTypeFirebase}

	err := auth.registerAuthType(firebase.authType, firebase)
	if err != nil {
		return nil, log.WrapActionError(log.ActionRegister, typeAuthType, nil, err)
	}

	return firebase, nil
}
