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
	authTypeUsername string = "username"
)

// Username implementation of authType
type usernameAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *usernameAuthImpl) signUp(authType model.AuthType, appOrg model.ApplicationOrganization, creds string, params string, newCredentialID string, l *logs.Log) (string, map[string]interface{}, error) {
	return "", nil, nil
}

func (a *usernameAuthImpl) signUpAdmin(authType model.AuthType, appOrg model.ApplicationOrganization, identifier string, password string, newCredentialID string) (map[string]interface{}, map[string]interface{}, error) {
	return nil, nil, nil
}

func (a *usernameAuthImpl) getUserIdentifier(creds string) (string, error) {
	return "", nil
}

func (a *usernameAuthImpl) verifyCredential(credential *model.Credential, verification string, l *logs.Log) (map[string]interface{}, error) {
	return nil, errors.New(logutils.Unimplemented)
}

func (a *usernameAuthImpl) sendVerifyCredential(credential *model.Credential, appName string, l *logs.Log) error {
	return nil
}

func (a *usernameAuthImpl) restartCredentialVerification(credential *model.Credential, appName string, l *logs.Log) error {
	return nil
}

func (a *usernameAuthImpl) isCredentialVerified(credential *model.Credential, l *logs.Log) (*bool, *bool, error) {
	return nil, nil, nil
}

func (a *usernameAuthImpl) checkCredentials(accountAuthType model.AccountAuthType, creds string, l *logs.Log) (string, error) {
	return "", nil
}

func (a *usernameAuthImpl) resetCredential(credential *model.Credential, resetCode *string, params string, l *logs.Log) (map[string]interface{}, error) {
	return nil, nil
}

func (a *usernameAuthImpl) forgotCredential(credential *model.Credential, identifier string, appName string, l *logs.Log) (map[string]interface{}, error) {
	return nil, nil
}

// initUsernameAuth initializes and registers a new username auth instance
func initUsernameAuth(auth *Auth) (*usernameAuthImpl, error) {
	username := &usernameAuthImpl{auth: auth, authType: authTypeUsername}

	err := auth.registerAuthType(username.authType, username)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return username, nil
}
