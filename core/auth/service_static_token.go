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

func (s *staticTokenServiceAuthImpl) checkCredentials(r *http.Request, _ []byte, creds interface{}, params map[string]interface{}) (*string, []model.ServiceAccount, error) {
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

	accounts, err := s.auth.storage.FindServiceAccounts(params)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAccount, nil, err)
	}
	if len(accounts) == 0 {
		return nil, nil, errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccount, nil)
	}

	accountCreds := accounts[0].Credentials
	if len(accountCreds) == 0 {
		message := "service account credentials missing"
		return &message, nil, errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccountCredential, nil)
	}

	for _, credential := range accountCreds {
		if credential.Type == ServiceAuthTypeStaticToken && credential.Params != nil {
			storedToken, ok := credential.Secrets["token"].(string)
			if !ok {
				return nil, nil, errors.WrapErrorAction(logutils.ActionParse, TypeStaticTokenCreds, nil, err)
			}
			if encodedToken == storedToken {
				return nil, accounts, nil
			}
		}
	}

	message := "invalid token"
	return &message, nil, errors.ErrorData(logutils.StatusInvalid, "service account token", nil)
}

func (s *staticTokenServiceAuthImpl) addCredentials(creds *model.ServiceAccountCredential) (map[string]interface{}, error) {
	if creds == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccountCredential, nil)
	}

	token, err := s.auth.buildRefreshToken()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeToken, nil, err)
	}

	encodedToken := s.hashAndEncodeToken(token)

	now := time.Now().UTC()
	id, _ := uuid.NewUUID()

	creds.ID = id.String()
	creds.Secrets = map[string]interface{}{
		"token": encodedToken,
	}
	creds.DateCreated = now

	displayParams := map[string]interface{}{
		"token": token,
	}

	return displayParams, nil
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
