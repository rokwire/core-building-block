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

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

const (
	//AuthTypeCode code auth type
	AuthTypeCode string = "code"

	typeAuthenticationCode string = "authentication code"
)

// Code implementation of authType
type codeAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *codeAuthImpl) signUp(identifierImpl identifierType, appName string, creds authCreds, params string, newCredentialID string) (string, map[string]interface{}, error) {
	credType, cred := creds.getCredential()
	if credType != AuthTypeCode {
		return "", nil, errors.ErrorData(logutils.StatusInvalid, "credential type", logutils.StringArgs(credType))
	}

	message, err := identifierImpl.sendCode(creds.identifier(), appName, cred, typeAuthenticationCode, newCredentialID)
	if err != nil {
		return "", nil, err
	}

	return message, nil, nil
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

func (a *codeAuthImpl) checkCredential(identifierImpl identifierType, credential *model.Credential, incomingCreds authCreds, appName string) (string, error) {
	var credID string
	var storedCredType string
	var storedCred string
	if credential != nil {
		credID = credential.ID
		storedCreds, err := identifierImpl.mapToCreds(credential.Value)
		if err != nil {
			return "", errors.WrapErrorAction(logutils.ActionCast, "map to code creds", nil, err)
		}

		storedCredType, storedCred = storedCreds.getCredential()
		if storedCredType != "" && storedCredType != AuthTypeCode {
			return "", errors.ErrorData(logutils.StatusInvalid, "credential type", logutils.StringArgs(storedCredType))
		}
	}

	incomingCredType, incomingCred := incomingCreds.getCredential()
	if incomingCredType != AuthTypeCode {
		return "", errors.ErrorData(logutils.StatusInvalid, "credential type", logutils.StringArgs(incomingCredType))
	}
	if storedCred != "" && incomingCred != storedCred {
		return "", errors.ErrorData(logutils.StatusInvalid, "credential", logutils.StringArgs(incomingCred))
	}

	message, err := identifierImpl.sendCode(incomingCreds.identifier(), appName, incomingCred, typeAuthenticationCode, credID)
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
