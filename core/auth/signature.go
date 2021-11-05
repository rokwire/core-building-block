package auth

import (
	"core-building-block/core/model"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

const (
	//AuthTypeSignature signature auth type
	AuthTypeSignature string = "signature"
)

//Signature implementation of authType
type signatureAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *signatureAuthImpl) signUp(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, newCredentialID string, l *logs.Log) (string, map[string]interface{}, error) {
	return "", nil, nil
}

func (a *signatureAuthImpl) getUserIdentifier(creds string) (string, error) {
	return "", nil
}

func (a *signatureAuthImpl) verify(credential *model.Credential, verification string, l *logs.Log) (map[string]interface{}, error) {
	return nil, errors.New(logutils.Unimplemented)
}
func (a *signatureAuthImpl) checkCredentials(accountAuthType model.AccountAuthType, creds string, l *logs.Log) (string, *bool, error) {
	return "", nil, nil
}

func (a *signatureAuthImpl) sendVerify(authType model.AuthType, identifier string, credential *model.Credential, verifyWaitTime int64, l *logs.Log) (map[string]interface{}, error) {
	return nil, nil
}

//initSignatureAuth initializes and registers a new signature auth instance
func initSignatureAuth(auth *Auth) (*signatureAuthImpl, error) {
	signature := &signatureAuthImpl{auth: auth, authType: AuthTypeSignature}

	err := auth.registerAuthType(signature.authType, signature)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return signature, nil
}
