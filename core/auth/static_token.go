package auth

import (
	"core-building-block/core/model"
	"core-building-block/utils"
	"net/http"
	"time"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

const (
	//ServiceAuthTypeStaticToken static token service auth type
	ServiceAuthTypeStaticToken string = "static_token"
	//TypeStaticTokenCreds type static token creds
	TypeStaticTokenCreds logutils.MessageDataType = "static token creds"
)

//staticTokenCreds represents the creds struct for static token auth
type staticTokenCreds struct {
	Token string `json:"token" validate:"required"`
}

// Static token implementation of serviceAuthType
type staticTokenServiceAuthImpl struct {
	auth            *Auth
	serviceAuthType string
}

func (s *staticTokenServiceAuthImpl) checkCredentials(r *http.Request, l *logs.Log) (*string, *model.ServiceAccount, error) {
	//TODO: parse tokenCreds from request
	var tokenCreds staticTokenCreds

	// err := json.Unmarshal([]byte(creds), &tokenCreds)
	// if err != nil {
	// 	return nil, nil, errors.WrapErrorAction(logutils.ActionUnmarshal, TypeStaticTokenCreds, nil, err)
	// }

	// validate := validator.New()
	// err = validate.Struct(tokenCreds)
	// if err != nil {
	// 	return nil, nil, errors.WrapErrorAction(logutils.ActionValidate, TypeStaticTokenCreds, nil, err)
	// }

	hashedToken := utils.SHA256Hash([]byte(tokenCreds.Token))
	account, err := s.auth.storage.FindServiceAccountByToken(string(hashedToken))
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAccount, nil, err)
	}

	return nil, account, nil
}

func (s *staticTokenServiceAuthImpl) addCredentials(account *model.ServiceAccount, creds *model.ServiceAccountCredential, l *logs.Log) (*model.ServiceAccount, error) {
	if account == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccount, nil)
	}
	if creds == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccountCredential, nil)
	}

	token, _, err := s.auth.buildRefreshToken()
	if err != nil {
		l.Info("error generating service account token")
		return nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeToken, nil, err)
	}

	creds.Token = &token
	creds.PubKey = nil
	creds.DateCreated = time.Now().UTC()
	account.Credentials = append(account.Credentials, *creds)

	return account, nil
}

//initStaticTokenServiceAuth initializes and registers a new static token service auth instance
func initStaticTokenServiceAuth(auth *Auth) (*staticTokenServiceAuthImpl, error) {
	staticToken := &staticTokenServiceAuthImpl{auth: auth, serviceAuthType: ServiceAuthTypeStaticToken}

	err := auth.registerServiceAuthType(staticToken.serviceAuthType, staticToken)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeServiceAuthType, nil, err)
	}

	return staticToken, nil
}
