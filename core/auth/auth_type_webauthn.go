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
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logs"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

const (
	authTypeWebAuthn string = "webauthn"
)

type webAuthnCred struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
}

type webAuthnUser struct {
	ID          string
	Name        string
	DisplayName string
	Credentials []webauthn.Credential
}

// WebAuthnID unique user ID
func (u webAuthnUser) WebAuthnID() []byte {
	return []byte(u.ID)
}

// WebAuthnName unique human-readable username
func (u webAuthnUser) WebAuthnName() string {
	return u.Name
}

// WebAuthnDisplayName user display name (display purposes only)
func (u webAuthnUser) WebAuthnDisplayName() string {
	return u.DisplayName
}

// WebAuthnCredentials
func (u webAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// WebAuthnIcon deprecated
func (u webAuthnUser) WebAuthnIcon() string {
	return ""
}

// WebAuthn implementation of authType
type webAuthnAuthImpl struct {
	auth     *Auth
	authType string
}

func buildWebAuthn(appOrg model.ApplicationOrganization) (*webauthn.WebAuthn, error) {
	//TODO: Figure out how to dynamically populate params
	wconfig := &webauthn.Config{
		RPDisplayName: appOrg.Application.Name,                           // Display Name for your site
		RPID:          "university.rokmetro.com",                         // Generally the FQDN for your site
		RPOrigins:     []string{"https://login.university.rokmetro.com"}, // The origin URLs allowed for WebAuthn requests
	}

	auth, err := webauthn.New(wconfig)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInitialize, model.TypeAuthType, nil, err)
	}

	return auth, nil
}

func (a *webAuthnAuthImpl) getUserIdentifier(creds string) (string, error) {
	return "", nil
}

func (a *webAuthnAuthImpl) signUp(authType model.AuthType, appOrg model.ApplicationOrganization, creds string, params string, newCredentialID string, l *logs.Log) (string, map[string]interface{}, error) {
	auth, err := buildWebAuthn(appOrg)
	if err != nil {
		return "", nil, err
	}

	user := webAuthnUser{}
	options, session, err := auth.BeginRegistration(user)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAccount, nil, err)
	}

	credData := map[string]interface{}{
		"session": session,
	}

	optionData, err := json.Marshal(options)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionMarshal, "creation options", nil, err)
	}

	return string(optionData), credData, nil
}

func (a *webAuthnAuthImpl) checkCredentials(accountAuthType model.AccountAuthType, creds string, l *logs.Log) (string, error) {
	if accountAuthType.Credential.Value == nil {
		return "", errors.ErrorData(logutils.StatusInvalid, model.TypeCredential, logutils.StringArgs(accountAuthType.Credential.ID))
	}

	auth, err := buildWebAuthn(accountAuthType.Account.AppOrg)
	if err != nil {
		return "", err
	}

	if accountAuthType.Credential.Value["session"] == nil {
		if accountAuthType.Credential.Value["credential"] == nil {
			return "", errors.ErrorData(logutils.StatusInvalid, model.TypeCredential, logutils.StringArgs(accountAuthType.Credential.ID))
		}
		return a.beginLogin(auth, accountAuthType, creds, l)
	}

	sessionRaw := accountAuthType.Credential.Value["session"]
	sessionJSON, err := json.Marshal(sessionRaw)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionMarshal, "session", nil, err)
	}
	var session webauthn.SessionData
	err = json.Unmarshal(sessionJSON, &session)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, "session", nil, err)
	}

	if accountAuthType.Credential.Value["credential"] == nil {
		return "", a.completeRegistration(auth, session, accountAuthType, creds, l)
	}

	return "", a.completeLogin(auth, session, accountAuthType, creds, l)
}

func (a *webAuthnAuthImpl) completeRegistration(auth *webauthn.WebAuthn, session webauthn.SessionData, accountAuthType model.AccountAuthType, creds string, l *logs.Log) error {
	response, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(creds))
	if err != nil {
		return err
	}

	user := webAuthnUser{}
	credential, err := auth.CreateCredential(user, session, response)
	if err != nil {
		return err
	}

	accountAuthType.Credential.Value = map[string]interface{}{
		"credential": credential,
	}
	a.auth.storage.UpdateCredential(nil, accountAuthType.Credential)

	return nil
}

func (a *webAuthnAuthImpl) beginLogin(auth *webauthn.WebAuthn, accountAuthType model.AccountAuthType, creds string, l *logs.Log) (string, error) {
	user := webAuthnUser{}
	options, session, err := auth.BeginLogin(user)
	if err != nil {
		return "", err
	}

	accountAuthType.Credential.Value["session"] = session
	a.auth.storage.UpdateCredential(nil, accountAuthType.Credential)

	optionData, err := json.Marshal(options)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionMarshal, "creation options", nil, err)
	}

	return string(optionData), nil
}

func (a *webAuthnAuthImpl) completeLogin(auth *webauthn.WebAuthn, session webauthn.SessionData, accountAuthType model.AccountAuthType, creds string, l *logs.Log) error {
	user := webAuthnUser{}
	response, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(creds))
	if err != nil {
		return err
	}

	_, err = auth.ValidateLogin(user, session, response)
	if err != nil {
		return err
	}

	return nil
}

func (a *webAuthnAuthImpl) signUpAdmin(authType model.AuthType, appOrg model.ApplicationOrganization, identifier string, password string, newCredentialID string) (map[string]interface{}, map[string]interface{}, error) {
	return nil, nil, nil
}

func (a *webAuthnAuthImpl) verifyCredential(credential *model.Credential, verification string, l *logs.Log) (map[string]interface{}, error) {
	return nil, errors.New(logutils.Unimplemented)
}

func (a *webAuthnAuthImpl) sendVerifyCredential(credential *model.Credential, appName string, l *logs.Log) error {
	return nil
}

func (a *webAuthnAuthImpl) restartCredentialVerification(credential *model.Credential, appName string, l *logs.Log) error {
	return nil
}

func (a *webAuthnAuthImpl) isCredentialVerified(credential *model.Credential, l *logs.Log) (*bool, *bool, error) {
	return nil, nil, nil
}

func (a *webAuthnAuthImpl) resetCredential(credential *model.Credential, resetCode *string, params string, l *logs.Log) (map[string]interface{}, error) {
	return nil, nil
}

func (a *webAuthnAuthImpl) forgotCredential(credential *model.Credential, identifier string, appName string, l *logs.Log) (map[string]interface{}, error) {
	return nil, nil
}

// initUsernameAuth initializes and registers a new username auth instance
func initWebAuthnAuth(auth *Auth) (*webAuthnAuthImpl, error) {
	webauthn := &webAuthnAuthImpl{auth: auth, authType: authTypeWebAuthn}

	err := auth.registerAuthType(webauthn.authType, webauthn)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAuthType, logutils.StringArgs(authTypeWebAuthn), err)
	}

	return webauthn, nil
}
