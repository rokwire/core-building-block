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

func (a *signatureAuthImpl) userExist(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, l *logs.Log) (*model.Account, *model.AccountAuthType, error) {
	return nil, nil, nil
}

func (a *signatureAuthImpl) checkCredentials(userAuthType model.AccountAuthType, creds string, l *logs.Log) (*bool, error) {
	return nil, nil
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
