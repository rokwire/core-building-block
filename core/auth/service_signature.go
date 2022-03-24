package auth

import (
	"core-building-block/core/model"
	"core-building-block/utils"
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

func (s *signatureServiceAuthImpl) checkCredentials(r *http.Request, body []byte, _ interface{}, params map[string]interface{}) ([]model.ServiceAccount, error) {
	accounts, err := s.auth.storage.FindServiceAccounts(params)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAccount, nil, err)
	}
	if len(accounts) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccount, nil).SetStatus(utils.ErrorStatusNotFound)
	}

	for _, credential := range accounts[0].Credentials {
		if credential.Type == ServiceAuthTypeSignature && credential.Params != nil {
			pubKeyPem, ok := credential.Params["pub_key"].(string)
			if !ok {
				s.auth.logger.ErrorWithFields("error asserting stored public key is string", logutils.Fields{"pub_key": credential.Params["pub_key"]})
				continue
			}
			pubKeyPem = strings.ReplaceAll(pubKeyPem, `\n`, "\n")

			pubKey, err := jwt.ParseRSAPublicKeyFromPEM([]byte(pubKeyPem))
			if err != nil {
				s.auth.logger.ErrorWithFields("error parsing stored public key", logutils.Fields{"pub_key": credential.Params["pub_key"]})
				continue
			}

			err = s.auth.SignatureAuth.CheckRequestSignature(r, body, pubKey)
			if err == nil {
				return accounts, nil
			}
		}
	}

	return nil, errors.WrapErrorAction(logutils.ActionValidate, "request signature", nil, err).SetStatus(utils.ErrorStatusInvalid)
}

func (s *signatureServiceAuthImpl) addCredentials(creds *model.ServiceAccountCredential) (map[string]interface{}, error) {
	if creds == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccountCredential, nil)
	}

	now := time.Now().UTC()
	id, _ := uuid.NewUUID()

	creds.ID = id.String()
	creds.DateCreated = now

	return creds.Params, nil
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
