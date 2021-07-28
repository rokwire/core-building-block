package auth

import (
	"core-building-block/core/model"

	log "github.com/rokmetro/logging-library/loglib"
)

const (
	authTypeEmail string = "email"
)

// Email implementation of authType
type emailAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *emailAuthImpl) check(creds string, orgID string, appID string, params string, l *log.Log) (*model.UserAuth, error) {
	//TODO: Implement
	return nil, log.NewError("Unimplemented")
}

//refresh is enabled for email auth, but no operation is needed
func (a *emailAuthImpl) refresh(params interface{}, orgID string, appID string, l *log.Log) (interface{}, *int64, error) {
	return nil, nil, nil
}

func (a *emailAuthImpl) getLoginUrl(orgID string, appID string, redirectUri string, l *log.Log) (string, map[string]interface{}, error) {
	return "", nil, log.NewErrorf("get login url operation invalid for auth_type=%s", a.authType)
}

//initEmailAuth initializes and registers a new email auth instance
func initEmailAuth(auth *Auth) (*emailAuthImpl, error) {
	email := &emailAuthImpl{auth: auth, authType: authTypeEmail}

	err := auth.registerAuthType(email.authType, email)
	if err != nil {
		return nil, log.WrapActionError(log.ActionRegister, typeAuthType, nil, err)
	}

	return email, nil
}
