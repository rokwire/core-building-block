package auth

import (
	"core-building-block/core/model"

	log "github.com/rokmetro/logging-library/loglib"
)

const (
	authTypeApiKey string = "api_key"
)

//API Key implementation of authType
type apiKeyAuthImpl struct {
	auth *Auth
}

func (a *apiKeyAuthImpl) check(creds string, params string, l *log.Log) (*model.UserAuth, error) {
	//TODO: Implement
	return nil, log.NewError(log.Unimplemented)
}

func (a *apiKeyAuthImpl) refresh(refreshToken string, l *log.Log) (*model.UserAuth, error) {
	return nil, log.NewErrorf("refresh operation invalid for auth_type=%s", authTypeApiKey)
}

//initAPIKeyAuth initializes and registers a new API key auth instance
func initAPIKeyAuth(auth *Auth) (*apiKeyAuthImpl, error) {
	apiKey := &apiKeyAuthImpl{auth: auth}

	err := auth.registerAuthType(authTypeApiKey, apiKey)
	if err != nil {
		return nil, log.WrapActionError(log.ActionRegister, typeAuthType, nil, err)
	}

	return apiKey, nil
}
