package auth

import (
	"errors"
)

//API Key implementation of authType
type apiKeyAuthImpl struct {
	auth *Auth
}

func (a *apiKeyAuthImpl) check(creds string) (*Claims, error) {
	//TODO: Implement
	return nil, errors.New("Unimplemented")
}

//initApiKeyAuth initializes and registers a new API key auth instance
func initApiKeyAuth(auth *Auth) (*apiKeyAuthImpl, error) {
	api_key := &apiKeyAuthImpl{auth: auth}

	err := auth.registerAuthType("api_key", api_key)
	if err != nil {
		return nil, err
	}

	return api_key, nil
}
