package auth

import (
	"errors"
)

//API Key implementation of authType
type apiKeyAuthImpl struct {
	auth *Auth
}

func (a *apiKeyAuthImpl) check(creds string, params string) (*UserAuth, error) {
	//TODO: Implement
	return nil, errors.New("Unimplemented")
}

//initAPIKeyAuth initializes and registers a new API key auth instance
func initAPIKeyAuth(auth *Auth) (*apiKeyAuthImpl, error) {
	apiKey := &apiKeyAuthImpl{auth: auth}

	err := auth.registerAuthType("api_key", apiKey)
	if err != nil {
		return nil, err
	}

	return apiKey, nil
}
