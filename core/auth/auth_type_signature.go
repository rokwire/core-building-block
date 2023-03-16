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
	"github.com/rokwire/logging-library-go/v2/logs"
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

func (a *signatureAuthImpl) code() string {
	return a.authType
}

func (a *signatureAuthImpl) signUp(appOrg model.ApplicationOrganization, creds string, params string, newCredentialID string, l *logs.Log) (string, map[string]interface{}, error) {
	return "", nil, nil
}

func (a *signatureAuthImpl) signUpAdmin(appOrg model.ApplicationOrganization, identifier string, password string, newCredentialID string) (map[string]interface{}, map[string]interface{}, error) {
	return nil, nil, nil
}

func (a *signatureAuthImpl) getUserIdentifier(creds string) (string, error) {
	return "", nil
}

func (a *signatureAuthImpl) verifyCredential(credential *model.Credential, verification string, l *logs.Log) (map[string]interface{}, error) {
	return nil, errors.New(logutils.Unimplemented)
}

func (a *signatureAuthImpl) sendVerifyCredential(appOrg model.ApplicationOrganization, credential *model.Credential, l *logs.Log) error {
	return nil
}

func (a *signatureAuthImpl) restartCredentialVerification(credential *model.Credential, appName string, l *logs.Log) error {
	return nil
}

func (a *signatureAuthImpl) isCredentialVerified(appOrg model.ApplicationOrganization, credential *model.Credential, l *logs.Log) (bool, *bool, error) {
	return true, nil, nil
}

func (a *signatureAuthImpl) checkCredentials(accountAuthType model.AccountAuthType, creds string, l *logs.Log) (string, error) {
	return "", nil
}

func (a *signatureAuthImpl) resetCredential(credential *model.Credential, resetCode *string, params string, l *logs.Log) (map[string]interface{}, error) {
	return nil, nil
}

func (a *signatureAuthImpl) forgotCredential(credential *model.Credential, identifier string, appName string, l *logs.Log) (map[string]interface{}, error) {
	return nil, nil
}

// initSignatureAuth initializes and registers a new signature auth instance
func initSignatureAuth(auth *Auth) (*signatureAuthImpl, error) {
	signature := &signatureAuthImpl{auth: auth, authType: AuthTypeSignature}

	err := auth.registerAuthType(signature.authType, signature)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeInternalAuthType, nil, err)
	}

	return signature, nil
}
