package auth

import (
	"core-building-block/core/model"
	"core-building-block/utils"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
	"gopkg.in/go-playground/validator.v9"
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

func (s *staticTokenServiceAuthImpl) checkCredentials(r *http.Request, creds interface{}, l *logs.Log) (*string, *model.ServiceAccount, error) {
	credsData, err := json.Marshal(creds)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionMarshal, TypeStaticTokenCreds, nil, err)
	}

	var tokenCreds staticTokenCreds
	err = json.Unmarshal([]byte(credsData), &tokenCreds)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionUnmarshal, TypeStaticTokenCreds, nil, err)
	}

	validate := validator.New()
	err = validate.Struct(tokenCreds)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionValidate, TypeStaticTokenCreds, nil, err)
	}

	encodedToken := s.hashAndEncodeToken(tokenCreds.Token)

	account, err := s.auth.storage.FindServiceAccountByToken(string(encodedToken))
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAccount, nil, err)
	}

	return nil, account, nil
}

func (s *staticTokenServiceAuthImpl) addCredentials(account *model.ServiceAccount, creds *model.ServiceAccountCredential, l *logs.Log) (*model.ServiceAccount, string, error) {
	if account == nil {
		return nil, "", errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccount, nil)
	}
	if creds == nil {
		return nil, "", errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccountCredential, nil)
	}

	token, _, err := s.auth.buildRefreshToken()
	if err != nil {
		l.Info("error generating service account token")
		return nil, "", errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeToken, nil, err)
	}

	encodedToken := s.hashAndEncodeToken(token)

	now := time.Now().UTC()
	id, _ := uuid.NewUUID()

	creds.ID = id.String()
	creds.Params = map[string]interface{}{
		"token": encodedToken,
	}
	creds.DateCreated = now
	account.Credentials = append(account.Credentials, *creds)

	return account, token, nil
}

func (s *staticTokenServiceAuthImpl) hiddenParams() []string {
	return []string{"token"}
}

func (s *staticTokenServiceAuthImpl) hashAndEncodeToken(token string) string {
	hashedToken := utils.SHA256Hash([]byte(token))
	return base64.StdEncoding.EncodeToString(hashedToken)
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
