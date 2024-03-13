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
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
	"gopkg.in/go-playground/validator.v9"
)

const (
	//IdentifierTypeUsername username identifier type
	IdentifierTypeUsername string = "username"

	typeUsernameIdentifier logutils.MessageDataType = "username identifier"
)

type usernameIdentifier struct {
	Username string `json:"username" validate:"required"`
}

// Username implementation of identifierType
type usernameIdentifierImpl struct {
	auth *Auth
	code string

	identifier string
}

func (a *usernameIdentifierImpl) getCode() string {
	return a.code
}

func (a *usernameIdentifierImpl) getIdentifier() string {
	return a.identifier
}

func (a *usernameIdentifierImpl) withIdentifier(creds string) (identifierType, error) {
	var requestCreds usernameIdentifier
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeUsernameIdentifier, nil, err)
	}

	err = validator.New().Struct(requestCreds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, typeUsernameIdentifier, nil, err)
	}

	username := strings.TrimSpace(strings.ToLower(requestCreds.Username))

	// some applications may append -<platform> to usernames to support cross-platform passkeys - we just want the raw username
	platforms := []string{"android", "ios", "web"}
	if usernameParts := strings.Split(username, "-"); len(usernameParts) > 1 && utils.Contains(platforms, usernameParts[len(usernameParts)-1]) {
		username = strings.Join(usernameParts[:len(usernameParts)-1], "-")
	}

	return &usernameIdentifierImpl{auth: a.auth, code: a.code, identifier: username}, nil
}

func (a *usernameIdentifierImpl) buildIdentifier(accountID *string, appName string) (string, *model.AccountIdentifier, error) {
	if a.identifier == "" {
		return "", nil, errors.ErrorData(logutils.StatusMissing, "username identifier", nil)
	}

	accountIDStr := ""
	if accountID != nil {
		accountIDStr = *accountID
	} else {
		accountIDStr = uuid.NewString()
	}

	accountIdentifier := model.AccountIdentifier{ID: uuid.NewString(), Code: a.code, Identifier: a.identifier, Verified: true,
		Account: model.Account{ID: accountIDStr}, DateCreated: time.Now().UTC()}

	return "", &accountIdentifier, nil
}

func (a *usernameIdentifierImpl) maskIdentifier() (string, error) {
	return a.identifier, nil
}

func (a *usernameIdentifierImpl) requireVerificationForSignIn() bool {
	return true
}

func (a *usernameIdentifierImpl) checkVerified(accountIdentifier *model.AccountIdentifier, appName string) error {
	return nil // return nil because username verification is not possible for now
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
