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
	"strconv"
	"strings"

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

const (
	//AuthTypeCode code auth type
	AuthTypeCode string = "code"

	credentialKeyCode      string = "code"
	typeAuthenticationCode string = "authentication code"
)

// Code implementation of authType
type codeAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *codeAuthImpl) signUp(identifierImpl identifierType, appName string, creds authCreds, params string, config map[string]interface{}, newCredentialID string) (string, map[string]interface{}, bool, error) {
	identifierChannel, _ := identifierImpl.(authCommunicationChannel)
	if identifierChannel == nil {
		return "", nil, false, errors.ErrorData(logutils.StatusInvalid, typeIdentifierType, logutils.StringArgs(identifierImpl.getType()))
	}

	code := ""
	if identifierChannel.requiresCodeGeneration() {
		code = strconv.Itoa(utils.GenerateRandomInt(1000000))
		padLen := 6 - len(code)
		if padLen > 0 {
			code = strings.Repeat("0", padLen) + code
		}

		//TODO: store generated codes in credentials collection?
	}

	message, err := identifierChannel.sendCode(creds.identifier(), appName, code, typeAuthenticationCode, newCredentialID)
	if err != nil {
		return "", nil, false, err
	}

	return message, nil, false, nil
}

func (a *codeAuthImpl) signUpAdmin(identifierImpl identifierType, appName string, creds authCreds, newCredentialID string) (map[string]interface{}, map[string]interface{}, error) {
	return nil, nil, errors.New(logutils.Unimplemented)
}

func (a *codeAuthImpl) forgotCredential(identifierImpl identifierType, credential authCreds, appName string, credID string) (map[string]interface{}, error) {
	return nil, errors.New(logutils.Unimplemented)
}

func (a *codeAuthImpl) resetCredential(credential authCreds, resetCode *string, params string) (map[string]interface{}, error) {
	return nil, errors.New(logutils.Unimplemented)
}

func (a *codeAuthImpl) checkCredential(identifierImpl identifierType, credential *model.Credential, incomingCreds authCreds, displayName string, appName string, config map[string]interface{}) (string, error) {
	identifierChannel, _ := identifierImpl.(authCommunicationChannel)
	if identifierChannel == nil {
		return "", errors.ErrorData(logutils.StatusInvalid, typeIdentifierType, logutils.StringArgs(identifierImpl.getType()))
	}

	var credID string
	var storedCred string
	if credential != nil {
		credID = credential.ID
		storedCreds, err := identifierImpl.mapToCreds(credential.Value)
		if err != nil {
			return "", errors.WrapErrorAction(logutils.ActionCast, "map to code creds", nil, err)
		}

		storedCred := storedCreds.getCredential(credentialKeyCode)
		if storedCred == "" {
			return "", errors.ErrorData(logutils.StatusMissing, logutils.MessageDataType(credentialKeyCode), nil)
		}
	}

	incomingCred := incomingCreds.getCredential(credentialKeyCode)
	if identifierChannel.requiresCodeGeneration() {
		if incomingCred == "" {
			return "", errors.ErrorData(logutils.StatusMissing, logutils.MessageDataType(credentialKeyCode), nil)
		}
		if incomingCred != storedCred {
			return "", errors.ErrorData(logutils.StatusInvalid, "credential", logutils.StringArgs(incomingCred))
		}
		return "", nil
	}

	message, err := identifierChannel.sendCode(incomingCreds.identifier(), appName, incomingCred, typeAuthenticationCode, credID)
	if err != nil {
		return "", err
	}
	return message, nil
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
