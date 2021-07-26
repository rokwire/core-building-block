package auth

import (
	"core-building-block/core/model"

	log "github.com/rokmetro/logging-library/loglib"
)

// Email implementation of authType
type emailAuthImpl struct {
	auth *Auth
}

func (a *emailAuthImpl) check(creds string, params string, l *log.Log) (*model.UserAuth, error) {
	//TODO: Implement
	return nil, log.NewError("Unimplemented")
}

func (a *emailAuthImpl) set(user *model.User, params string) error {
	return log.NewError(log.Unimplemented)
}

//initEmailAuth initializes and registers a new email auth instance
func initEmailAuth(auth *Auth) (*emailAuthImpl, error) {
	email := &emailAuthImpl{auth: auth}

	err := auth.registerAuthType("email", email)
	if err != nil {
		return nil, log.WrapActionError(log.ActionRegister, typeAuthType, nil, err)
	}

	return email, nil
}
