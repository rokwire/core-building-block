package auth

import (
	"core-building-block/core/model"

	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logs"
	"github.com/rokmetro/logging-library/logutils"
)

const (
	authTypeAPIKey string = "api_key"
)

//API Key implementation of authType
type apiKeyAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *apiKeyAuthImpl) check(creds string, orgID string, appID string, params string, l *logs.Log) (*model.UserAuth, interface{}, error) {
	//TODO: Implement
	return nil, nil, errors.New(logutils.Unimplemented)
}

func (a *apiKeyAuthImpl) refresh(params interface{}, orgID string, appID string, l *logs.Log) (*model.UserAuth, interface{}, error) {
	return nil, nil, errors.Newf("refresh operation invalid for auth_type=%s", authTypeAPIKey)
}

func (a *apiKeyAuthImpl) getLoginURL(orgID string, appID string, redirectURI string, l *logs.Log) (string, map[string]interface{}, error) {
	return "", nil, errors.Newf("get login url operation invalid for auth_type=%s", a.authType)
}

//initAPIKeyAuth initializes and registers a new API key auth instance
func initAPIKeyAuth(auth *Auth) (*apiKeyAuthImpl, error) {
	apiKey := &apiKeyAuthImpl{auth: auth, authType: authTypeAPIKey}

	err := auth.registerAuthType(apiKey.authType, apiKey)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return apiKey, nil
}
