package auth

import (
	"core-building-block/core/model"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logs"
	"github.com/rokmetro/logging-library/logutils"
	"gopkg.in/go-playground/validator.v9"
)

const (
	//AuthTypeAPIKey api key auth type
	AuthTypeAPIKey string = "api_key"

	typeAPIKeyCreds logutils.MessageDataType = "api key creds"
)

//API Key implementation of authType
type apiKeyAuthImpl struct {
	auth     *Auth
	authType string
}

type apiKeyCreds struct {
	APIKey             string `json:"api_key" validate:"required"`
	AnonymousProfileID string `json:"anonymous_profile_id"`
}

type apiKeyResponseParams struct {
	AnonymousProfileID string `json:"anonymous_profile_id"`
}

func (a *apiKeyAuthImpl) check(creds string, orgID string, appID string, params string, l *logs.Log) (*model.UserAuth, error) {
	var keyCreds apiKeyCreds
	err := json.Unmarshal([]byte(keyCreds.APIKey), &keyCreds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeAPIKeyCreds, nil, err)
	}

	validate := validator.New()
	err = validate.Struct(keyCreds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, typeAPIKeyCreds, nil, err)
	}

	apiKey, err := a.auth.getAPIKey(keyCreds.APIKey)
	if err != nil || apiKey == nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeAPIKey, nil, err)
	}

	if apiKey.AppID != appID || apiKey.OrgID != orgID {
		return nil, errors.Newf("incorrect key for org_id=%v, app_id=%v", orgID, appID)
	}

	userAuth := model.UserAuth{Sub: keyCreds.AnonymousProfileID, Anonymous: true}
	if keyCreds.AnonymousProfileID == "" {
		id, err := uuid.NewUUID()
		if err != nil {
			return nil, errors.WrapErrorAction("generating", "uuid", logutils.StringArgs("anonymous profile id"), err)
		}
		userAuth.Sub = id.String()
		userAuth.ResponseParams = &apiKeyResponseParams{AnonymousProfileID: userAuth.Sub}
	}

	return &userAuth, nil
}

func (a *apiKeyAuthImpl) refresh(params map[string]interface{}, orgID string, appID string, l *logs.Log) (*model.UserAuth, error) {
	return nil, errors.Newf("refresh operation invalid for auth_type=%s", a.authType)
}

func (a *apiKeyAuthImpl) getLoginURL(orgID string, appID string, redirectURI string, l *logs.Log) (string, map[string]interface{}, error) {
	return "", nil, errors.Newf("get login url operation invalid for auth_type=%s", a.authType)
}

func (a *apiKeyAuthImpl) isGlobal() bool {
	return false
}

//initAPIKeyAuth initializes and registers a new API key auth instance
func initAPIKeyAuth(auth *Auth) (*apiKeyAuthImpl, error) {
	apiKey := &apiKeyAuthImpl{auth: auth, authType: AuthTypeAPIKey}

	err := auth.registerAuthType(apiKey.authType, apiKey)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return apiKey, nil
}
