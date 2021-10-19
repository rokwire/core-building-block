package auth

import (
	"core-building-block/core/model"
	"encoding/json"

	"github.com/google/uuid"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
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
	AnonymousID string `json:"anonymous_id"`
}

func (a *apiKeyAuthImpl) checkCredentials(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, l *logs.Log) (string, map[string]interface{}, error) {
	var keyCreds apiKeyCreds
	err := json.Unmarshal([]byte(creds), &keyCreds)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeAPIKeyCreds, nil, err)
	}

	anonymousID := keyCreds.AnonymousID
	if anonymousID == "" {
		anonymousUUID, _ := uuid.NewUUID()
		anonymousID = anonymousUUID.String()
	}

	params := map[string]interface{}{}
	params["anonymous_id"] = anonymousID
	return anonymousID, params, nil
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
