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
	"core-building-block/core/model"
	"core-building-block/utils"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/rokwire/core-auth-library-go/v2/sigauth"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
	"gopkg.in/go-playground/validator.v9"
)

const (
	//ServiceAuthTypeStaticToken static token service auth type
	ServiceAuthTypeStaticToken string = "static_token"
	//TypeStaticTokenCreds type static token creds
	TypeStaticTokenCreds logutils.MessageDataType = "static token creds"
)

// staticTokenCreds represents the creds struct for static token auth
type staticTokenCreds struct {
	Token string `json:"token" validate:"required"`
}

// Static token implementation of serviceAuthType
type staticTokenServiceAuthImpl struct {
	auth            *Auth
	serviceAuthType string
}

func (s *staticTokenServiceAuthImpl) checkCredentials(_ *sigauth.Request, creds interface{}, params map[string]interface{}) ([]model.ServiceAccount, error) {
	credsData, err := json.Marshal(creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, TypeStaticTokenCreds, nil, err)
	}

	var tokenCreds staticTokenCreds
	err = json.Unmarshal([]byte(credsData), &tokenCreds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, TypeStaticTokenCreds, nil, err)
	}

	validate := validator.New()
	err = validate.Struct(tokenCreds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, TypeStaticTokenCreds, nil, err).SetStatus(utils.ErrorStatusInvalid)
	}

	encodedToken := s.auth.hashAndEncodeToken(tokenCreds.Token)

	accounts, err := s.auth.storage.FindServiceAccounts(params)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAccount, nil, err)
	}
	if len(accounts) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccount, nil).SetStatus(utils.ErrorStatusNotFound)
	}

	for _, credential := range accounts[0].Credentials {
		if credential.Type == ServiceAuthTypeStaticToken && credential.Secrets != nil {
			storedToken, ok := credential.Secrets["token"].(string)
			if !ok {
				s.auth.logger.ErrorWithFields("error asserting stored static token is string", logutils.Fields{"token": credential.Secrets["token"]})
				continue
			}
			if encodedToken == storedToken {
				return accounts, nil
			}
		}
	}

	return nil, errors.ErrorData(logutils.StatusInvalid, "service account token", nil).SetStatus(utils.ErrorStatusInvalid)
}

func (s *staticTokenServiceAuthImpl) addCredentials(creds *model.ServiceAccountCredential) (map[string]interface{}, error) {
	if creds == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeServiceAccountCredential, nil)
	}

	token, err := s.auth.buildRefreshToken()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeToken, nil, err)
	}

	creds.ID = uuid.NewString()
	creds.Secrets = map[string]interface{}{
		"token": s.auth.hashAndEncodeToken(token),
	}
	creds.DateCreated = time.Now().UTC()

	displayParams := map[string]interface{}{
		"token": token,
	}
	return displayParams, nil
}

// initStaticTokenServiceAuth initializes and registers a new static token service auth instance
func initStaticTokenServiceAuth(auth *Auth) (*staticTokenServiceAuthImpl, error) {
	staticToken := &staticTokenServiceAuthImpl{auth: auth, serviceAuthType: ServiceAuthTypeStaticToken}

	err := auth.registerServiceAuthType(staticToken.serviceAuthType, staticToken)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeServiceAuthType, nil, err)
	}

	return staticToken, nil
}
