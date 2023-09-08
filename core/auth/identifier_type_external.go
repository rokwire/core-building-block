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

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

const (
	//IdentifierTypeExternal external identifier type
	IdentifierTypeExternal string = "external"

	typeExternalIdentifier logutils.MessageDataType = "external identifier"
)

// External implementation of identifierType
type externalIdentifierImpl struct {
	auth *Auth
	code string

	identifier string
}

func (a *externalIdentifierImpl) getCode() string {
	return a.code
}

func (a *externalIdentifierImpl) getIdentifier() string {
	return a.identifier
}

func (a *externalIdentifierImpl) withIdentifier(creds string) (identifierType, error) {
	var requestCreds map[string]string
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeExternalIdentifier, nil, err)
	}

	// these are keys that should NOT be treated as external identifier codes
	excludeKeys := []string{IdentifierTypeEmail, IdentifierTypePhone, IdentifierTypeUsername, AuthTypePassword, AuthTypeCode, credentialKeyResponse}
	for k, id := range requestCreds {
		if !utils.Contains(excludeKeys, k) {
			return &externalIdentifierImpl{auth: a.auth, code: k, identifier: strings.TrimSpace(id)}, nil
		}
	}

	return nil, errors.ErrorData(logutils.StatusMissing, "external identifier", nil)
}

func (a *externalIdentifierImpl) buildIdentifier(accountID *string, appName string) (string, *model.AccountIdentifier, error) {
	return "", nil, errors.ErrorData(logutils.StatusInvalid, typeIdentifierType, nil)
}

func (a *externalIdentifierImpl) requireVerificationForSignIn() bool {
	return true
}

func (a *externalIdentifierImpl) checkVerified(accountIdentifier *model.AccountIdentifier, appName string) error {
	return nil
}

func (a *externalIdentifierImpl) allowMultiple() bool {
	return true
}

// initExternalIdentifier initializes and registers a new external identifier instance
func initExternalIdentifier(auth *Auth) (*externalIdentifierImpl, error) {
	external := &externalIdentifierImpl{auth: auth, code: IdentifierTypeExternal}

	err := auth.registerIdentifierType(external.code, external)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeIdentifierType, nil, err)
	}

	return external, nil
}
