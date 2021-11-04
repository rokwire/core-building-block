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
	//AuthTypeAnonymous api key auth type
	AuthTypeAnonymous string = "anonymous"

	typeAnonymousCreds logutils.MessageDataType = "anonymous creds"
)

//API Key implementation of authType
type anonymousAuthImpl struct {
	auth     *Auth
	authType string
}

type anonymousCreds struct {
	AnonymousID string `json:"anonymous_id"`
}

func (a *anonymousAuthImpl) checkCredentials(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, l *logs.Log) (string, map[string]interface{}, error) {
	var keyCreds anonymousCreds
	err := json.Unmarshal([]byte(creds), &keyCreds)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeAnonymousCreds, nil, err)
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

//initAnonymousAuth initializes and registers a new API key auth instance
func initAnonymousAuth(auth *Auth) (*anonymousAuthImpl, error) {
	anonymous := &anonymousAuthImpl{auth: auth, authType: AuthTypeAnonymous}

	err := auth.registerAnonymousAuthType(anonymous.authType, anonymous)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return anonymous, nil
}
