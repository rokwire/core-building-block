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
	"encoding/json"
	"time"

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

const (
	//IdentifierTypeUsername username identifier type
	IdentifierTypeUsername string = "username"

	typeUsernameCreds  logutils.MessageDataType = "username creds"
	typeUsernameParams logutils.MessageDataType = "username params"
)

// userNameCreds represents the creds struct for username identifier
type usernameCreds struct {
	Username string  `json:"username" bson:"username" validate:"required"`
	Password *string `json:"password" bson:"password,omitempty"`
	Code     *string `json:"code" bson:"code,omitempty"`
}

func (c *usernameCreds) identifier() string {
	return c.Username
}

func (c *usernameCreds) getCredential() (string, string) {
	if c.Password != nil {
		return AuthTypePassword, *c.Password
	} else if c.Code != nil {
		return AuthTypeCode, *c.Code
	}
	return "", ""
}

func (c *usernameCreds) setCredential(value string, credType string) {
	if credType == AuthTypePassword {
		c.Password = &value
	} else if credType == AuthTypeCode {
		c.Code = &value
	}
}

func (c *usernameCreds) getVerificationParams() (string, *time.Time) {
	return "", nil
}

func (c *usernameCreds) setVerificationParams(code string, expiry *time.Time) {}

func (c *usernameCreds) getResetParams() (string, *time.Time) {
	return "", nil
}

func (c *usernameCreds) setResetParams(code string, expiry *time.Time) {}

func (c *usernameCreds) toMap() (map[string]interface{}, error) {
	credBytes, err := json.Marshal(c)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typeUsernameCreds, nil, err)
	}
	var credsMap map[string]interface{}
	err = json.Unmarshal(credBytes, &credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, "username creds map", nil, err)
	}
	return credsMap, nil
}

type usernameParams struct {
	ConfirmPassword *string `json:"confirm_password"`
}

func (p *usernameParams) parameter() (string, string) {
	if p.ConfirmPassword != nil {
		return AuthTypePassword, *p.ConfirmPassword
	}
	return "", ""
}

// Username implementation of identifierType
type usernameIdentifierImpl struct {
	auth           *Auth
	identifierType string
}

func (a *usernameIdentifierImpl) getUserIdentifier(creds string) (string, error) {
	var requestCreds usernameCreds
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, typeUsernameCreds, nil, err)
	}

	return requestCreds.Username, nil
}

func (a *usernameIdentifierImpl) parseCreds(creds string) (authCreds, error) {
	var credential usernameCreds
	err := json.Unmarshal([]byte(creds), &credential)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeUsernameCreds, nil, err)
	}

	if len(credential.Username) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, typeUsernameCreds, logutils.StringArgs("username"))
	}
	if credType, cred := credential.getCredential(); len(credType) == 0 || len(cred) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, typeUsernameCreds, logutils.StringArgs("credential"))
	}

	return &credential, nil
}

func (a *usernameIdentifierImpl) parseParams(params string) (authParams, error) {
	var parameters usernameParams
	err := json.Unmarshal([]byte(params), &parameters)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeUsernameParams, nil, err)
	}

	if paramType, param := parameters.parameter(); len(paramType) == 0 || len(param) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, typeUsernameParams, logutils.StringArgs("parameter"))
	}

	return &parameters, nil
}

func (a *usernameIdentifierImpl) mapToCreds(credsMap map[string]interface{}) (authCreds, error) {
	credBytes, err := json.Marshal(credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, "username creds map", nil, err)
	}
	var creds usernameCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeUsernameCreds, nil, err)
	}
	return &creds, nil
}

func (a *usernameIdentifierImpl) buildCredential(identifier string, credential string, credType string) authCreds {
	if credType == AuthTypePassword {
		return &usernameCreds{Username: identifier, Password: &credential}
	}
	return nil
}

func (a *usernameIdentifierImpl) verifyCredential(credential authCreds, verification string) (map[string]interface{}, error) {
	return nil, errors.New(logutils.Unimplemented)
}

func (a *usernameIdentifierImpl) sendVerifyCredential(credential authCreds, appName string, credID string) (map[string]interface{}, bool, error) {
	return nil, false, errors.New(logutils.Unimplemented)
}

func (a *usernameIdentifierImpl) restartCredentialVerification(credential authCreds, appName string, credID string) (map[string]interface{}, error) {
	return nil, errors.New(logutils.Unimplemented)
}

func (a *usernameIdentifierImpl) isCredentialVerified(credential *model.Credential) (*bool, *bool, error) {
	//TODO verification process for usernames
	verified := true
	expired := false
	return &verified, &expired, nil
}

func (a *usernameIdentifierImpl) sendCode(identifier string, appName string, code string, codeType string, credID string) (string, error) {
	return "", errors.New(logutils.Unimplemented)
}

// initUsernameIdentifier initializes and registers a new username identifier instance
func initUsernameIdentifier(auth *Auth) (*usernameIdentifierImpl, error) {
	username := &usernameIdentifierImpl{auth: auth, identifierType: IdentifierTypeUsername}

	err := auth.registerIdentifierType(username.identifierType, username)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeIdentifierType, nil, err)
	}

	return username, nil
}
