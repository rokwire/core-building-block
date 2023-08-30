// Copyright 2023 Board of Trustees of the University of Illinois.
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
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
	"gopkg.in/go-playground/validator.v9"
)

const (
	//AuthTypeCode code auth type
	AuthTypeCode string = "code"

	typeAuthenticationCode string = "authentication code"

	stateKeyCode string = "code"

	typeCodeCreds logutils.MessageDataType = "code creds"
)

// codeCreds represents the creds struct for code authentication
type codeCreds struct {
	Code *string `json:"code,omitempty"`
}

// Code implementation of authType
type codeAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *codeAuthImpl) signUp(identifierImpl identifierType, accountID *string, appOrg model.ApplicationOrganization, creds string, params string) (string, *model.AccountIdentifier, *model.Credential, error) {
	identifierChannel, _ := identifierImpl.(authCommunicationChannel)
	if identifierChannel == nil {
		return "", nil, nil, errors.ErrorData(logutils.StatusInvalid, typeIdentifierType, logutils.StringArgs(identifierImpl.getCode()))
	}

	if accountID != nil {
		return "", nil, nil, nil
	}

	// we are not linking a code credential, so use the accountID generated for the identifier
	message, accountIdentifier, err := identifierImpl.buildIdentifier(nil, appOrg.Application.Name)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction("building", "identifier", logutils.StringArgs(identifierImpl.getCode()), err)
	}

	return message, accountIdentifier, nil, nil
}

func (a *codeAuthImpl) signUpAdmin(identifierImpl identifierType, appOrg model.ApplicationOrganization, creds string) (map[string]interface{}, *model.AccountIdentifier, *model.Credential, error) {
	return nil, nil, nil, errors.New(logutils.Unimplemented)
}

func (a *codeAuthImpl) forgotCredential(identifierImpl identifierType, credential *model.Credential, appOrg model.ApplicationOrganization) (map[string]interface{}, error) {
	return nil, errors.New(logutils.Unimplemented)
}

func (a *codeAuthImpl) resetCredential(credential *model.Credential, resetCode *string, params string) (map[string]interface{}, error) {
	return nil, errors.New(logutils.Unimplemented)
}

func (a *codeAuthImpl) checkCredentials(identifierImpl identifierType, accountID *string, credentials []model.Credential, creds string, appOrg model.ApplicationOrganization) (string, string, error) {
	identifierChannel, _ := identifierImpl.(authCommunicationChannel)
	if identifierChannel == nil {
		return "", "", errors.ErrorData(logutils.StatusInvalid, typeIdentifierType, logutils.StringArgs(identifierImpl.getCode()))
	}

	incomingCreds, err := a.parseCreds(creds)
	if err != nil {
		return "", "", errors.WrapErrorAction(logutils.ActionParse, typeCodeCreds, nil, err)
	}
	incomingCode := ""
	if incomingCreds.Code != nil {
		incomingCode = *incomingCreds.Code
	}

	if identifierChannel.requiresCodeGeneration() {
		if incomingCode == "" {
			// generate a new code
			code := strconv.Itoa(utils.GenerateRandomInt(1000000))
			padLen := 6 - len(code)
			if padLen > 0 {
				code = strings.Repeat("0", padLen) + code
			}

			// store generated codes in login state collection
			state := map[string]interface{}{stateKeyCode: code}
			loginState := model.LoginState{ID: uuid.NewString(), AppID: appOrg.Application.ID, OrgID: appOrg.Organization.ID, AccountID: accountID, State: state, DateCreated: time.Now().UTC()}
			err := a.auth.storage.InsertLoginState(loginState)
			if err != nil {
				return "", "", errors.WrapErrorAction(logutils.ActionCreate, model.TypeLoginState, nil, err)
			}
		} else {
			params := map[string]interface{}{
				stateKeyCode: *incomingCreds.Code,
			}
			loginState, err := a.auth.storage.FindLoginState(appOrg.Application.ID, appOrg.Organization.ID, accountID, params)
			if err != nil {
				return "", "", errors.WrapErrorAction(logutils.ActionFind, model.TypeLoginState, nil, err)
			}

			if loginState == nil {
				return "", "", errors.ErrorData(logutils.StatusInvalid, "code", logutils.StringArgs(*incomingCreds.Code))
			}

			return "", "", nil
		}
	}

	message, err := identifierChannel.sendCode(appOrg.Application.Name, incomingCode, typeAuthenticationCode, "")
	if err != nil {
		return "", "", err
	}

	return message, "", nil
}

func (a *codeAuthImpl) withParams(params map[string]interface{}) (authType, error) {
	return a, nil
}

func (a *codeAuthImpl) allowMultiple() bool {
	return false
}

// Helpers

func (a *codeAuthImpl) parseCreds(creds string) (*codeCreds, error) {
	var credential codeCreds
	err := json.Unmarshal([]byte(creds), &credential)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeCodeCreds, nil, err)
	}
	err = validator.New().Struct(credential)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, typeCodeCreds, nil, err)
	}
	return &credential, nil
}

func (a *codeAuthImpl) mapToCreds(credsMap map[string]interface{}) (*codeCreds, error) {
	creds, err := utils.JSONConvert[codeCreds, map[string]interface{}](credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionParse, typeCodeCreds, nil, err)
	}

	err = validator.New().Struct(creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, typeCodeCreds, nil, err)
	}
	return creds, nil
}

// initCodeAuth initializes and registers a new code auth instance
func initCodeAuth(auth *Auth) (*codeAuthImpl, error) {
	code := &codeAuthImpl{auth: auth, authType: AuthTypeCode}

	err := auth.registerAuthType(code.authType, code)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAuthType, nil, err)
	}

	return code, nil
}
