package auth

import (
	"core-building-block/core/model"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
)

const (
	//ServiceAuthTypeSignature signature service auth type
	ServiceAuthTypeSignature string = "signature"
	//TypeSignatureCreds type signature creds
	TypeSignatureCreds logutils.MessageDataType = "signature creds"
)

// Signature implementation of serviceAuthType
type signatureServiceAuthImpl struct {
	auth            *Auth
	serviceAuthType string
}

func (s *signatureServiceAuthImpl) checkCredentials(r *http.Request, body []byte, _ interface{}, params map[string]interface{}) (*string, []model.ServiceAccount, error) {
	accounts, err := s.auth.storage.FindServiceAccounts(params)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAccount, nil, err)
	}
	if len(accounts) == 0 {
		return nil, nil, errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccount, nil)
	}

	for _, credential := range accounts[0].Credentials {
		if credential.Type == ServiceAuthTypeSignature && credential.Params != nil {
			pubKeyPem, ok := credential.Params["pub_key"].(string)
			if !ok || pubKeyPem == "" {
				continue
			}
			pubKeyPem = strings.ReplaceAll(pubKeyPem, `\n`, "\n")

			pubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pubKeyPem))
			if err != nil {
				return nil, nil, errors.WrapErrorAction(logutils.ActionParse, "service account public key", nil, err)
			}

			err = s.auth.SignatureAuth.CheckRequestSignature(r, body, pubKey)
			if err == nil {
				return nil, accounts, nil
			}
		}
	}

	message := "invalid signature"
	return &message, nil, errors.WrapErrorAction(logutils.ActionValidate, "request signature", nil, err)
}

func (s *signatureServiceAuthImpl) addCredentials(creds *model.ServiceAccountCredential) (string, error) {
	if creds == nil {
		return "", errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccountCredential, nil)
	}

	now := time.Now().UTC()
	id, _ := uuid.NewUUID()

	creds.ID = id.String()
	creds.DateCreated = now

	return "", nil
}

// no hidden params for signature service auth
func (s *signatureServiceAuthImpl) hiddenParams() []string {
	return nil
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
