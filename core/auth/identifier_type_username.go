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

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

const (
	//IdentifierTypeUsername username identifier type
	IdentifierTypeUsername string = "username"

	typeUsernameCreds  logutils.MessageDataType = "username creds"
	typeUsernameParams logutils.MessageDataType = "username params"
)

// Username implementation of identifierType
type usernameIdentifierImpl struct {
	identifierType string
}

// userNameCreds represents the creds struct for username identifier
type usernameCreds struct {
	Username string `json:"username" bson:"username" validate:"required"`
	Password string `json:"password" bson:"password"`
}

func (c *usernameCreds) identifier() string {
	return c.Username
}

func (c *usernameCreds) credential() string {
	return c.Password
}

func (a *usernameIdentifierImpl) getUserIdentifier(creds string) (string, error) {
	var requestCreds usernameCreds
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, typeUsernameCreds, nil, err)
	}

	return requestCreds.Username, nil
}

// initUsernameIdentifier initializes and registers a new username identifier instance
func initUsernameIdentifier(auth *Auth) (*usernameIdentifierImpl, error) {
	username := &usernameIdentifierImpl{identifierType: IdentifierTypeUsername}

	err := auth.registerIdentifierType(username.identifierType, username)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeIdentifierType, nil, err)
	}

	return username, nil
}
