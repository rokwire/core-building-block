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

func (a *codeAuthImpl) signUp(identifierImpl identifierType, appName string, creds string, params string, config map[string]interface{}, newCredentialID string) (string, *model.AccountIdentifier, map[string]interface{}, bool, error) {
	identifierChannel, _ := identifierImpl.(authCommunicationChannel)
	if identifierChannel == nil {
		return "", nil, nil, false, errors.ErrorData(logutils.StatusInvalid, typeIdentifierType, logutils.StringArgs(identifierImpl.getCode()))
	}

	code := ""
	if identifierChannel.requiresCodeGeneration() {
		code = strconv.Itoa(utils.GenerateRandomInt(1000000))
		padLen := 6 - len(code)
		if padLen > 0 {
			code = strings.Repeat("0", padLen) + code
		}

		//TODO: store generated codes in login state collection or auth types in account?
	}

	identifier, err := identifierImpl.getUserIdentifier("")
	if err != nil {
		return "", nil, nil, false, errors.WrapErrorAction(logutils.ActionGet, "identifier", logutils.StringArgs(identifierImpl.getCode()), err)
	}
	accountIdentifier := model.AccountIdentifier{ID: uuid.NewString(), Code: identifierImpl.getCode(), Identifier: identifier, DateCreated: time.Now().UTC()}

	message, err := identifierChannel.sendCode(appName, code, typeAuthenticationCode, newCredentialID)
	if err != nil {
		return "", nil, nil, false, err
	}

	return message, &accountIdentifier, nil, false, nil
}

func (a *codeAuthImpl) signUpAdmin(identifierImpl identifierType, appName string, creds string, newCredentialID string) (*model.AccountIdentifier, map[string]interface{}, map[string]interface{}, error) {
	return nil, nil, nil, errors.New(logutils.Unimplemented)
}

func (a *codeAuthImpl) forgotCredential(identifierImpl identifierType, credential *model.Credential, appName string) (map[string]interface{}, error) {
	return nil, errors.New(logutils.Unimplemented)
}

func (a *codeAuthImpl) resetCredential(credential *model.Credential, resetCode *string, params string) (map[string]interface{}, error) {
	return nil, errors.New(logutils.Unimplemented)
}

func (a *codeAuthImpl) checkCredential(identifierImpl identifierType, accountIdentifier *model.AccountIdentifier, credential *model.Credential, creds string, displayName string, appName string, config map[string]interface{}) (string, error) {
	identifierChannel, _ := identifierImpl.(authCommunicationChannel)
	if identifierChannel == nil {
		return "", errors.ErrorData(logutils.StatusInvalid, typeIdentifierType, logutils.StringArgs(identifierImpl.getCode()))
	}

	var credID string
	var storedCred string
	if credential != nil {
		credID = credential.ID
		storedCreds, err := a.mapToCreds(credential.Value)
		if err != nil {
			return "", errors.WrapErrorAction(logutils.ActionCast, "map to code creds", nil, err)
		}
		if storedCreds.Code == nil {
			return "", errors.ErrorData(logutils.StatusMissing, "stored code", nil)
		}
		storedCred = *storedCreds.Code
	}

	incomingCreds, err := a.parseCreds(creds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionParse, typeCodeCreds, nil, err)
	}
	if incomingCreds.Code == nil {
		return "", errors.ErrorData(logutils.StatusMissing, "incoming code", nil)
	}
	if identifierChannel.requiresCodeGeneration() {
		if *incomingCreds.Code != storedCred {
			return "", errors.ErrorData(logutils.StatusInvalid, "credential", logutils.StringArgs(*incomingCreds.Code))
		}

		accountIdentifier.Verified = true
		return "", nil
	}

	message, err := identifierChannel.sendCode(appName, *incomingCreds.Code, typeAuthenticationCode, credID)
	if err != nil {
		return "", err
	}

	accountIdentifier.Verified = true
	return message, nil
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
	credBytes, err := json.Marshal(credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, "webauthn creds map", nil, err)
	}
	var creds codeCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeCodeCreds, nil, err)
	}

	err = validator.New().Struct(creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, typeCodeCreds, nil, err)
	}
	return &creds, nil
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
