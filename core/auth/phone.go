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

func (a *phoneAuthImpl) check(creds string, orgID string, appID string, params string, l *logs.Log) (*model.UserAuth, error) {
	//TODO: Implement
	return nil, errors.New(logutils.Unimplemented)
}

//refresh is enabled for phone auth, but no operation is needed
func (a *phoneAuthImpl) refresh(params interface{}, orgID string, appID string, l *logs.Log) (*model.UserAuth, error) {
	return nil, nil
}

func (a *phoneAuthImpl) getLoginURL(orgID string, appID string, redirectURI string, l *logs.Log) (string, map[string]interface{}, error) {
	return "", nil, errors.Newf("get login url operation invalid for auth_type=%s", a.authType)
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
