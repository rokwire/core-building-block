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
	"strings"

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
	"gopkg.in/go-playground/validator.v9"
)

const (
	//IdentifierTypeUsername username identifier type
	IdentifierTypeUsername string = "username"

	typeUsernameIdentifier logutils.MessageDataType = "username identifier"
	typeUsernameParams     logutils.MessageDataType = "username params"
)

type usernameIdentifier struct {
	Username string `json:"username" validate:"required"`
}

// Username implementation of identifierType
type usernameIdentifierImpl struct {
	auth *Auth
	code string

	identifier *string
}

func (a *usernameIdentifierImpl) getCode() string {
	return a.code
}

func (a *usernameIdentifierImpl) getUserIdentifier(creds string) (string, error) {
	if a.identifier != nil {
		return *a.identifier, nil
	}

	var requestCreds usernameIdentifier
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, typeUsernameIdentifier, nil, err)
	}

	err = validator.New().Struct(requestCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionValidate, typeUsernameIdentifier, nil, err)
	}

	username := strings.TrimSpace(strings.ToLower(requestCreds.Username))
	a.identifier = &username
	return username, nil
}

func (a *usernameIdentifierImpl) withIdentifier(identifier string) identifierType {
	return &usernameIdentifierImpl{auth: a.auth, code: a.code, identifier: &identifier}
}

func (a *usernameIdentifierImpl) allowMultiple() bool {
	return false
}

// initUsernameIdentifier initializes and registers a new username identifier instance
func initUsernameIdentifier(auth *Auth) (*usernameIdentifierImpl, error) {
	username := &usernameIdentifierImpl{auth: auth, code: IdentifierTypeUsername}

	err := auth.registerIdentifierType(username.code, username)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeIdentifierType, nil, err)
	}

	return username, nil
}
