package auth

import (
	"core-building-block/core/model"

	log "github.com/rokmetro/logging-library/loglib"
)

//API Key implementation of authType
type apiKeyAuthImpl struct {
	auth *Auth
}

func (a *apiKeyAuthImpl) check(creds string, params string, l *log.Log) (*model.UserAuth, error) {
	//TODO: Implement
	return nil, log.NewError(log.Unimplemented)
}

func (a *apiKeyAuthImpl) set(userAuth *model.UserAuth, orgID string, appID string) (*model.AuthCred, error) {
	return nil, log.NewError(log.Unimplemented)
}

//initAPIKeyAuth initializes and registers a new API key auth instance
func initAPIKeyAuth(auth *Auth) (*apiKeyAuthImpl, error) {
	apiKey := &apiKeyAuthImpl{auth: auth}

	err := auth.registerAuthType("api_key", apiKey)
	if err != nil {
		return nil, log.WrapActionError(log.ActionRegister, typeAuthType, nil, err)
	}

	return apiKey, nil
}
