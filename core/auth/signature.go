package auth

import (
	"core-building-block/core/model"
	"net/http"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

const (
	//AuthTypeSignature signature auth type
	AuthTypeSignature string = "signature"
	//ServiceAuthTypeSignature signature service auth type
	ServiceAuthTypeSignature string = "signature"
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

func (a *signatureAuthImpl) verifyCredential(credential *model.Credential, verification string, l *logs.Log) (map[string]interface{}, error) {
	return nil, errors.New(logutils.Unimplemented)
}

func (a *signatureAuthImpl) sendVerifyCredential(credential *model.Credential, l *logs.Log) error {
	return nil
}

func (a *signatureAuthImpl) restartCredentialVerification(credential *model.Credential, l *logs.Log) error {
	return nil
}

func (a *signatureAuthImpl) isCredentialVerified(credential *model.Credential, l *logs.Log) (*bool, *bool, error) {
	return nil, nil, nil
}

func (a *signatureAuthImpl) checkCredentials(accountAuthType model.AccountAuthType, creds string, l *logs.Log) (string, error) {
	return "", nil
}

func (a *signatureAuthImpl) resetCredential(credential *model.Credential, resetCode *string, params string, l *logs.Log) (map[string]interface{}, error) {
	return nil, nil
}

func (a *signatureAuthImpl) forgotCredential(credential *model.Credential, identifier string, l *logs.Log) (map[string]interface{}, error) {
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

// Signature implementation of serviceAuthType
type signatureServiceAuthImpl struct {
	auth            *Auth
	serviceAuthType string
}

func (s *signatureServiceAuthImpl) checkCredentials(r *http.Request, l *logs.Log) (*string, *model.ServiceAccount, error) {
	account, err := s.auth.storage.FindServiceAccountByID(nil, "")
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAccount, nil, err)
	}

	// err = s.auth.SignatureAuth.CheckRequestSignature(r, account.PubKey)
	// if err != nil {
	// 	return nil, nil, errors.WrapErrorAction(logutils.ActionValidate, "request signature", nil, err)
	// }

	return nil, account, nil
}

//initSignatureServiceAuth initializes and registers a new signature service auth instance
func initSignatureServiceAuth(auth *Auth) (*signatureServiceAuthImpl, error) {
	signature := &signatureServiceAuthImpl{auth: auth, serviceAuthType: ServiceAuthTypeStaticToken}

	err := auth.registerServiceAuthType(signature.serviceAuthType, signature)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeServiceAuthType, nil, err)
	}

	return signature, nil
}
