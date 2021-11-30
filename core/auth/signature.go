package auth

import (
	"core-building-block/core/model"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
	"gopkg.in/go-playground/validator.v9"
)

const (
	//AuthTypeSignature signature auth type
	AuthTypeSignature string = "signature"
	//ServiceAuthTypeSignature signature service auth type
	ServiceAuthTypeSignature string = "signature"
	//TypeSignatureCreds type signature creds
	TypeSignatureCreds logutils.MessageDataType = "signature creds"
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

//signatureCreds represents the creds struct for signature auth
type signatureCreds struct {
	ID string `json:"id" validate:"required"`
}

// Signature implementation of serviceAuthType
type signatureServiceAuthImpl struct {
	auth            *Auth
	serviceAuthType string
}

func (s *signatureServiceAuthImpl) checkCredentials(r *http.Request, creds interface{}, l *logs.Log) (*string, *model.ServiceAccount, error) {
	credsData, err := json.Marshal(creds)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionMarshal, TypeSignatureCreds, nil, err)
	}

	var sigCreds signatureCreds
	err = json.Unmarshal([]byte(credsData), &sigCreds)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionUnmarshal, TypeSignatureCreds, nil, err)
	}

	validate := validator.New()
	err = validate.Struct(sigCreds)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionValidate, TypeSignatureCreds, nil, err)
	}

	account, err := s.auth.storage.FindServiceAccountByID(nil, sigCreds.ID)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAccount, nil, err)
	}

	for _, credential := range account.Credentials {
		if credential.Type == ServiceAuthTypeSignature && credential.PubKey != nil {
			pubKeyPemString := strings.Replace(*credential.PubKey, `\n`, "\n", -1)

			pubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pubKeyPemString))
			if err != nil {
				return nil, nil, errors.WrapErrorAction(logutils.ActionParse, "service account public key", nil, err)
			}

			err = s.auth.SignatureAuth.CheckRequestSignature(r, pubKey)
			if err == nil {
				return nil, account, nil
			}

			l.WarnError("error checking request signature", err)
		}
	}

	return nil, nil, errors.WrapErrorAction(logutils.ActionValidate, "request signature", nil, err)
}

func (s *signatureServiceAuthImpl) addCredentials(account *model.ServiceAccount, creds *model.ServiceAccountCredential, l *logs.Log) (*model.ServiceAccount, string, error) {
	if account == nil {
		return nil, "", errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccount, nil)
	}
	if creds == nil {
		return nil, "", errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccountCredential, nil)
	}

	creds.DateCreated = time.Now().UTC()
	account.Credentials = append(account.Credentials, *creds)

	return account, "", nil
}

//initSignatureServiceAuth initializes and registers a new signature service auth instance
func initSignatureServiceAuth(auth *Auth) (*signatureServiceAuthImpl, error) {
	signature := &signatureServiceAuthImpl{auth: auth, serviceAuthType: ServiceAuthTypeSignature}

	err := auth.registerServiceAuthType(signature.serviceAuthType, signature)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeServiceAuthType, nil, err)
	}

	return signature, nil
}
