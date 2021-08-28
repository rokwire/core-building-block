package auth

import (
	"core-building-block/core/model"

	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logs"
	"github.com/rokmetro/logging-library/logutils"
)

const (
	authTypeSignature string = "signature"
)

//Signature implementation of authType
type signatureAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *signatureAuthImpl) check(creds string, authType model.AuthType, appType model.ApplicationType, params string, l *logs.Log) (*model.UserAuth, error) {
	//TODO: Implement
	return nil, errors.New(logutils.Unimplemented)
}

func (a *signatureAuthImpl) refresh(params map[string]interface{}, orgID string, appID string, l *logs.Log) (*model.UserAuth, error) {
	return nil, errors.Newf("refresh operation invalid for auth_type=%s", authTypeSignature)
}

func (a *signatureAuthImpl) getLoginURL(authType model.AuthType, appType model.ApplicationType, redirectURI string, l *logs.Log) (string, map[string]interface{}, error) {
	return "", nil, errors.Newf("get login url operation invalid for auth_type=%s", a.authType)
}

//initSignatureAuth initializes and registers a new signature auth instance
func initSignatureAuth(auth *Auth) (*signatureAuthImpl, error) {
	signature := &signatureAuthImpl{auth: auth, authType: authTypeSignature}

	err := auth.registerAuthType(signature.authType, signature)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return signature, nil
}
