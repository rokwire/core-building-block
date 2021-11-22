package auth

import (
	"core-building-block/core/model"
	"crypto/rsa"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
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

	//TODO: which pub key to use if there are multiple?
	var pubKeyPem *string
	var pubKey *rsa.PublicKey
	if pubKeyPem != nil {
		pubKeyPemString := strings.Replace(*pubKeyPem, `\n`, "\n", -1)

		pubKey, err = jwt.ParseRSAPublicKeyFromPEM([]byte(pubKeyPemString))
		if err != nil {
			return nil, nil, errors.WrapErrorAction(logutils.ActionParse, "service account public key", nil, err)
		}
	}

	err = s.auth.SignatureAuth.CheckRequestSignature(r, pubKey)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionValidate, "request signature", nil, err)
	}

	return nil, account, nil
}

func (s *signatureServiceAuthImpl) addCredentials(account *model.ServiceAccount, creds *model.ServiceAccountCredential, l *logs.Log) (*model.ServiceAccount, error) {
	if account == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccount, nil)
	}
	if creds == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccountCredential, nil)
	}

	creds.DateCreated = time.Now().UTC()
	account.Credentials = append(account.Credentials, *creds)

	return account, nil
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
