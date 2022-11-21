// Copyright 2022 Board of Trustees of the University of Illinois.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"encoding/json"

	"github.com/google/uuid"
	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

const (
	//AuthTypeAnonymous api key auth type
	AuthTypeAnonymous string = "anonymous"

	typeAnonymousCreds logutils.MessageDataType = "anonymous creds"
)

// API Key implementation of authType
type anonymousAuthImpl struct {
	auth     *Auth
	authType string
}

type anonymousCreds struct {
	AnonymousID string `json:"anonymous_id"`
}

func (a *anonymousAuthImpl) checkCredentials(creds string) (string, map[string]interface{}, error) {
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

// initAnonymousAuth initializes and registers a new API key auth instance
func initAnonymousAuth(auth *Auth) (*anonymousAuthImpl, error) {
	anonymous := &anonymousAuthImpl{auth: auth, authType: AuthTypeAnonymous}

	err := auth.registerAnonymousAuthType(anonymous.authType, anonymous)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return anonymous, nil
}
