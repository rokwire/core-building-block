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
	//AuthTypeFirebase firebase auth type
	AuthTypeFirebase string = "firebase"
)

// Firebase implementation of authType
type firebaseAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *firebaseAuthImpl) signUp(identifierImpl identifierType, accountID *string, appOrg model.ApplicationOrganization, creds string, params string) (string, *model.AccountIdentifier, *model.Credential, error) {
	return "", nil, nil, nil
}

func (a *firebaseAuthImpl) signUpAdmin(identifierImpl identifierType, appOrg model.ApplicationOrganization, creds string) (map[string]interface{}, *model.AccountIdentifier, *model.Credential, error) {
	return nil, nil, nil, nil
}

func (a *firebaseAuthImpl) forgotCredential(identifierImpl identifierType, credential *model.Credential, appOrg model.ApplicationOrganization) (map[string]interface{}, error) {
	return nil, nil
}

func (a *firebaseAuthImpl) resetCredential(credential *model.Credential, resetCode *string, params string) (map[string]interface{}, error) {
	return nil, nil
}

func (a *firebaseAuthImpl) checkCredentials(identifierImpl identifierType, accountID *string, aats []model.AccountAuthType, creds string, params string, appOrg model.ApplicationOrganization) (string, string, error) {
	return "", "", nil
}

func (a *firebaseAuthImpl) withParams(params map[string]interface{}) (authType, error) {
	return a, nil
}

func (a *firebaseAuthImpl) requireIdentifierVerificationForSignIn() bool {
	return false
}

func (a *firebaseAuthImpl) allowMultiple() bool {
	return false
}

// initFirebaseAuth initializes and registers a new Firebase auth instance
func initFirebaseAuth(auth *Auth) (*firebaseAuthImpl, error) {
	firebase := &firebaseAuthImpl{auth: auth, authType: AuthTypeFirebase}

	err := auth.registerAuthType(firebase.authType, firebase)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAuthType, nil, err)
	}

	return firebase, nil
}
