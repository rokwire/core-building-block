package auth

import (
	"core-building-block/core/model"
	"encoding/json"
	"time"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
	"gopkg.in/go-playground/validator.v9"
)

const (
	//ServiceAuthTypeStaticToken static token service auth type
	ServiceAuthTypeStaticToken string = "static token"
	//TypeStaticTokenCreds type static token creds
	TypeStaticTokenCreds logutils.MessageDataType = "static token creds"
)

//staticTokenCreds represents the creds struct for static token auth
type staticTokenCreds struct {
	Token string `json:"token" validate:"required"`
}

// Static token implementation of serviceAuthType
type staticTokenAuthImpl struct {
	auth            *Auth
	serviceAuthType string
}

func (s *staticTokenAuthImpl) checkCredentials(creds string, l *logs.Log) (*string, *model.ServiceAccount, error) {
	var tokenCreds staticTokenCreds
	err := json.Unmarshal([]byte(creds), &tokenCreds)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionUnmarshal, TypeStaticTokenCreds, nil, err)
	}

	validate := validator.New()
	err = validate.Struct(tokenCreds)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionValidate, TypeStaticTokenCreds, nil, err)
	}

	account, err := s.auth.storage.FindServiceAccount(tokenCreds.Token)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAccount, nil, err)
	}

	if tokenCreds.Token != account.CurrentToken() {
		message := "previous token"
		//remove all tokens in storage?
		return &message, nil, errors.WrapErrorAction(logutils.ActionValidate, "service account token", nil, err)
	}
	if account.Expires.Before(time.Now().UTC()) {
		message := "token expired"
		return &message, nil, errors.ErrorData(logutils.StatusInvalid, "service account token", logutils.StringArgs("expired token"))
	}

	return nil, account, nil
}

//initStaticTokenAuth initializes and registers a new static token service auth instance
func initStaticTokenAuth(auth *Auth) (*staticTokenAuthImpl, error) {
	staticToken := &staticTokenAuthImpl{auth: auth, serviceAuthType: ServiceAuthTypeStaticToken}

	err := auth.registerServiceAuthType(staticToken.serviceAuthType, staticToken)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeServiceAuthType, nil, err)
	}

	return staticToken, nil
}
