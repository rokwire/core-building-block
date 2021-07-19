package auth

import (
	log "github.com/rokmetro/logging-library/loglib"
)

//API Key implementation of authType
type apiKeyAuthImpl struct {
	auth *Auth
}

func (a *apiKeyAuthImpl) check(creds string, params string, l *log.Log) (*UserAuth, error) {
	//TODO: Implement
	return nil, log.NewError(log.Unimplemented)
}

//initApiKeyAuth initializes and registers a new API key auth instance
func initApiKeyAuth(auth *Auth) (*apiKeyAuthImpl, error) {
	api_key := &apiKeyAuthImpl{auth: auth}

	err := auth.registerAuthType("api_key", api_key)
	if err != nil {
		return nil, log.WrapActionError(log.RegisterAction, typeAuthType, nil, err)
	}

	return api_key, nil
}
