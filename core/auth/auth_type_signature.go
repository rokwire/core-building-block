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

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

const (
	//AuthTypeSignature signature auth type
	AuthTypeSignature string = "signature"
)

// Signature implementation of authType
type signatureAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *signatureAuthImpl) signUp(identifierImpl identifierType, appOrg model.ApplicationOrganization, creds string, params string, config map[string]interface{}) (string, *model.AccountIdentifier, *model.Credential, error) {
	return "", nil, nil, nil
}

func (a *signatureAuthImpl) signUpAdmin(identifierImpl identifierType, appOrg model.ApplicationOrganization, creds string) (map[string]interface{}, *model.AccountIdentifier, *model.Credential, error) {
	return nil, nil, nil, nil
}

func (a *signatureAuthImpl) forgotCredential(identifierImpl identifierType, credential *model.Credential, appOrg model.ApplicationOrganization) (map[string]interface{}, error) {
	return nil, nil
}

func (a *signatureAuthImpl) resetCredential(credential *model.Credential, resetCode *string, params string) (map[string]interface{}, error) {
	return nil, nil
}

func (a *signatureAuthImpl) checkCredentials(identifierImpl identifierType, accountIdentifier *model.AccountIdentifier, credentials []model.Credential, creds string, displayName string, appOrg model.ApplicationOrganization, config map[string]interface{}) (string, string, error) {
	return "", "", nil
}

// initSignatureAuth initializes and registers a new signature auth instance
func initSignatureAuth(auth *Auth) (*signatureAuthImpl, error) {
	signature := &signatureAuthImpl{auth: auth, authType: AuthTypeSignature}

	err := auth.registerAuthType(signature.authType, signature)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAuthType, nil, err)
	}

	return signature, nil
}
