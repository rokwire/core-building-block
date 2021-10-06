package auth

import (
	"core-building-block/core/model"
	"strings"

	"github.com/google/uuid"
	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logs"
	"github.com/rokmetro/logging-library/logutils"
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

type apiKeyResponseParams struct {
	AnonymousID string `json:"anonymous_id"`
}

func (a *apiKeyAuthImpl) checkCredentials(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, anonymousID string, l *logs.Log) (string, interface{}, error) {
	creds = strings.ReplaceAll(creds, `"`, "")
	apiKey, err := a.auth.getCachedAPIKey(creds)
	if err != nil || apiKey == nil {
		return "", nil, errors.Newf("incorrect key for org_id=%v, app_id=%v", appOrg.Organization.ID, appOrg.Application.ID)
	}

	if apiKey.AppID != appOrg.Application.ID || apiKey.OrgID != appOrg.Organization.ID {
		return "", nil, errors.Newf("incorrect key for org_id=%v, app_id=%v", appOrg.Organization.ID, appOrg.Application.ID)
	}

	if anonymousID == "" {
		anonymousUUID, _ := uuid.NewUUID()
		anonymousID = anonymousUUID.String()
	}

	return anonymousID, apiKeyResponseParams{anonymousID}, nil
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
