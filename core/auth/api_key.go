package auth

import (
	"core-building-block/core/model"
	"encoding/json"

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

func (a *apiKeyAuthImpl) checkCredentials(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, l *logs.Log) (string, error) {
	var keyCreds apiKeyCreds
	err := json.Unmarshal([]byte(creds), &keyCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, typeAPIKeyCreds, nil, err)
	}

	validate := validator.New()
	err = validate.Struct(keyCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionValidate, typeAPIKeyCreds, nil, err)
	}

	apiKey, err := a.auth.getCachedAPIKey(keyCreds.APIKey)
	if err != nil || apiKey == nil {
		return "", errors.Newf("incorrect key for org_id=%v, app_id=%v", appOrg.Organization.ID, appOrg.Application.ID)
	}

	if apiKey.AppID != appOrg.Application.ID || apiKey.OrgID != appOrg.Organization.ID {
		return "", errors.Newf("incorrect key for org_id=%v, app_id=%v", appOrg.Organization.ID, appOrg.Application.ID)
	}

	return keyCreds.AnonymousProfileID, nil
}

//initAPIKeyAuth initializes and registers a new API key auth instance
func initAPIKeyAuth(auth *Auth) (*apiKeyAuthImpl, error) {
	apiKey := &apiKeyAuthImpl{auth: auth, authType: AuthTypeAPIKey}

	err := auth.registerAnonymousAuthType(apiKey.authType, apiKey)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return apiKey, nil
}
