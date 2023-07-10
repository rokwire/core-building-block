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
	Username   string  `json:"username" bson:"username" validate:"required"`
	Password   *string `json:"password,omitempty" bson:"password,omitempty"`
	Session    *string `json:"session,omitempty" bson:"session,omitempty"`
	Credential *string `json:"credential,omitempty" bson:"credential,omitempty"`
	Response   *string `json:"response,omitempty"`
	Code       *string `json:"code,omitempty" bson:"code,omitempty"`
}

func (c *usernameCreds) identifier() string {
	return c.Username
}

func (c *usernameCreds) getAuthType() string {
	if c.Password != nil {
		return AuthTypePassword
	} else if c.Code != nil {
		return AuthTypeCode
	} else if c.Session != nil || c.Credential != nil || c.Response != nil {
		return AuthTypeWebAuthn
	}
	return ""
}

func (c *usernameCreds) getCredential(key string) string {
	if key == credentialKeyCode && c.Code != nil {
		return *c.Code
	} else if key == credentialKeyPassword && c.Password != nil {
		return *c.Password
	} else if key == credentialKeyResponse && c.Response != nil {
		return *c.Response
	} else if key == credentialKeySession && c.Session != nil {
		return *c.Session
	} else if key == credentialKeyCredential && c.Credential != nil {
		return *c.Credential
	}
	return ""
}

func (c *usernameCreds) setCredential(value string, key string) {
	if key == credentialKeyCode {
		c.Code = &value
	} else if key == credentialKeyPassword {
		c.Password = &value
	} else if key == credentialKeyResponse {
		c.Response = &value
	} else if key == credentialKeySession {
		c.Session = &value
	} else if key == credentialKeyCredential {
		c.Credential = &value
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
	DisplayName     *string `json:"display_name"`
}

func (p *usernameParams) parameter(key string) string {
	if key == parameterKeyPassword && p.ConfirmPassword != nil {
		return *p.ConfirmPassword
	} else if key == parameterKeyDisplayName && p.DisplayName != nil {
		return *p.DisplayName
	}
	return ""
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

	return &credential, nil
}

func (a *usernameIdentifierImpl) parseParams(params string) (authParams, error) {
	var parameters usernameParams
	err := json.Unmarshal([]byte(params), &parameters)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeUsernameParams, nil, err)
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

func (a *usernameIdentifierImpl) buildCredential(identifier string, credential string, key string) authCreds {
	if key == credentialKeyCode {
		return &usernameCreds{Username: identifier, Code: &credential}
	} else if key == credentialKeyPassword {
		return &usernameCreds{Username: identifier, Password: &credential}
	} else if key == credentialKeySession {
		return &usernameCreds{Username: identifier, Session: &credential}
	} else if key == credentialKeyCredential {
		return &usernameCreds{Username: identifier, Credential: &credential}
	}
	return nil
}

func (a *usernameIdentifierImpl) verifyCredential(credential authCreds, verification string) (map[string]interface{}, error) {
	return nil, errors.New(logutils.Unimplemented)
}

func (a *usernameIdentifierImpl) sendVerifyCredential(credential authCreds, appName string, credID string) (map[string]interface{}, bool, error) {
	return nil, false, nil
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
