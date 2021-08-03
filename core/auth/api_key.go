package auth

import (
	"core-building-block/core/model"

	log "github.com/rokmetro/logging-library/loglib"
)

const (
	authTypeAPIKey string = "api_key"
)

//API Key implementation of authType
type apiKeyAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *apiKeyAuthImpl) check(creds string, orgID string, appID string, params string, l *log.Log) (*model.UserAuth, error) {
	//TODO: Implement
	return nil, log.NewError(log.Unimplemented)
}

func (a *apiKeyAuthImpl) refresh(refreshToken string, orgID string, appID string, l *log.Log) (*model.UserAuth, error) {
	return nil, log.NewErrorf("refresh operation invalid for auth_type=%s", authTypeAPIKey)
}

func (a *apiKeyAuthImpl) getLoginURL(orgID string, appID string, redirectURI string, l *log.Log) (string, map[string]interface{}, error) {
	return "", nil, log.NewErrorf("get login url operation invalid for auth_type=%s", a.authType)
}

//initAPIKeyAuth initializes and registers a new API key auth instance
func initAPIKeyAuth(auth *Auth) (*apiKeyAuthImpl, error) {
	apiKey := &apiKeyAuthImpl{auth: auth, authType: authTypeAPIKey}

	err := auth.registerAuthType(apiKey.authType, apiKey)
	if err != nil {
		return nil, log.WrapErrorAction(log.ActionRegister, typeAuthType, nil, err)
	}

	return apiKey, nil
}
