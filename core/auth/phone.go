package auth

import (
	"core-building-block/core/model"

	log "github.com/rokmetro/logging-library/loglib"
)

const (
	authTypePhone string = "phone"
)

// Phone implementation of authType
type phoneAuthImpl struct {
	auth *Auth
}

func (a *phoneAuthImpl) check(creds string, params string, l *log.Log) (*model.UserAuth, error) {
	//TODO: Implement
	return nil, log.NewError(log.Unimplemented)
}

//refresh is enabled for phone auth, but no operation is needed
func (a *phoneAuthImpl) refresh(refreshToken string, l *log.Log) (*model.UserAuth, error) {
	return nil, nil
}

//initPhoneAuth initializes and registers a new phone auth instance
func initPhoneAuth(auth *Auth) (*phoneAuthImpl, error) {
	phone := &phoneAuthImpl{auth: auth}

	err := auth.registerAuthType(authTypePhone, phone)
	if err != nil {
		return nil, log.WrapActionError(log.ActionRegister, typeAuthType, nil, err)
	}

	return phone, nil
}
