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
	//ServiceAuthTypeSignature signature service auth type
	ServiceAuthTypeSignature string = "signature"
	//TypeSignatureCreds type signature creds
	TypeSignatureCreds logutils.MessageDataType = "signature creds"
)

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
		if credential.Type == ServiceAuthTypeSignature && credential.Params != nil {
			pubKeyPem, ok := credential.Params["pub_key"].(string)
			if !ok || pubKeyPem == "" {
				continue
			}
			pubKeyPem = strings.Replace(pubKeyPem, `\n`, "\n", -1)

			pubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pubKeyPem))
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

func (s *signatureServiceAuthImpl) addCredentials(account *model.ServiceAccount, creds *model.ServiceAccountCredential, l *logs.Log) (*model.ServiceAccount, error) {
	if account == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccount, nil)
	}
	if creds == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccountCredential, nil)
	}

	now := time.Now().UTC()
	creds.DateCreated = now
	account.Credentials = append(account.Credentials, *creds)
	account.DateUpdated = &now

	return account, nil
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
