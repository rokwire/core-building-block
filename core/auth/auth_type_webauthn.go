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
	authTypeWebAuthn   string                   = "webauthn"
	typeWebAuthnCreds  logutils.MessageDataType = "webauthn creds"
	typeWebAuthnParams logutils.MessageDataType = "webauthn params"
)

type webAuthnCreds struct {
	Username string `json:"username"`
	Response string `json:"response"`
}

type webAuthnParams struct {
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

func buildWebAuthn(supportedAuthType model.SupportedAuthType, appOrg model.ApplicationOrganization) (*webauthn.WebAuthn, error) {
	rpID, ok := supportedAuthType.Params["rp_id"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusInvalid, "supported auth type param", &logutils.FieldArgs{"param": "rp_id", "app_org_id": appOrg.ID})
	}
	rpOrigins, ok := supportedAuthType.Params["rp_origins"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusInvalid, "supported auth type param", &logutils.FieldArgs{"param": "rp_origins", "app_org_id": appOrg.ID})
	}

	requireResidentKey, _ := supportedAuthType.Params["require_resident_key"].(bool)
	residentKey, ok := supportedAuthType.Params["resident_key"].(string)
	if !ok {
		residentKey = string(protocol.ResidentKeyRequirementRequired)
	}
	userVerification, ok := supportedAuthType.Params["user_verification"].(string)
	if !ok {
		userVerification = string(protocol.VerificationRequired)
	}
	attestationPreference, ok := supportedAuthType.Params["attestation_preference"].(string)
	if !ok {
		attestationPreference = string(protocol.PreferNoAttestation)
	}
	authenticatorAttachment, ok := supportedAuthType.Params["authenticator_attachment"].(string)
	if !ok {
		authenticatorAttachment = string(protocol.Platform)
	}

	wconfig := &webauthn.Config{
		RPDisplayName:         appOrg.Application.Name,       // Display Name for your site
		RPID:                  rpID,                          // Generally the FQDN for your site
		RPOrigins:             strings.Split(rpOrigins, ","), // The origin URLs allowed for WebAuthn requests
		AttestationPreference: protocol.ConveyancePreference(attestationPreference),
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			AuthenticatorAttachment: protocol.AuthenticatorAttachment(authenticatorAttachment),
			RequireResidentKey:      &requireResidentKey,
			ResidentKey:             protocol.ResidentKeyRequirement(residentKey),
			UserVerification:        protocol.UserVerificationRequirement(userVerification),
		},
	}

	auth, err := webauthn.New(wconfig)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInitialize, model.TypeAuthType, nil, err)
	}

	return auth, nil
}

func (a *webAuthnAuthImpl) signUp(identifierImpl identifierType, appName string, creds authCreds, params string, newCredentialID string) (string, map[string]interface{}, error) {
	auth, err := buildWebAuthn(supportedAuthType, appOrg)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionInitialize, logutils.MessageDataType(authTypeWebAuthn), nil, err)
	}

	var parsedCreds webAuthnCreds
	err = json.Unmarshal([]byte(creds), &parsedCreds)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionParse, typeWebAuthnCreds, nil, err)
	}
	if parsedCreds.Username == "" {
		return "", nil, errors.ErrorData(logutils.StatusMissing, "username", nil)
	}
	parsedCreds.Username = strings.TrimSpace(strings.ToLower(parsedCreds.Username))

	var parsedParams webAuthnParams
	err = json.Unmarshal([]byte(params), &parsedParams)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeWebAuthnParams, nil, err)
	}

	user := webAuthnUser{ID: newCredentialID, Name: parsedCreds.Username, DisplayName: parsedParams.DisplayName}
	return a.beginRegistration(auth, user)
}

func (a *webAuthnAuthImpl) checkCredential(identifierImpl identifierType, storedCreds *model.Credential, incomingCreds authCreds, appName string) (string, error) {
	if accountAuthType.Credential.Value == nil {
		return "", errors.ErrorData(logutils.StatusInvalid, model.TypeCredential, logutils.StringArgs(accountAuthType.Credential.ID))
	}

	var parsedCreds webAuthnCreds
	err := json.Unmarshal([]byte(creds), &parsedCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionParse, typeWebAuthnCreds, nil, err)
	}

	auth, err := buildWebAuthn(accountAuthType.SupportedAuthType, accountAuthType.Account.AppOrg)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionInitialize, logutils.MessageDataType(authTypeWebAuthn), nil, err)
	}

	user := webAuthnUser{ID: accountAuthType.Credential.ID, Name: accountAuthType.Identifier, DisplayName: accountAuthType.Account.Profile.GetFullName()}

	var credential *webauthn.Credential
	if accountAuthType.Credential.Value["credential"] != nil {
		credentialJSON, ok := accountAuthType.Credential.Value["credential"].(string)
		if !ok {
			return "", errors.ErrorData(logutils.StatusInvalid, "credential param", nil)
		}
		var credentialVal webauthn.Credential
		err = json.Unmarshal([]byte(credentialJSON), &credentialVal)
		if err != nil {
			return "", errors.WrapErrorAction(logutils.ActionUnmarshal, "credential", nil, err)
		}

		credential = &credentialVal
		user.Credentials = []webauthn.Credential{credentialVal}
	}

	if parsedCreds.Response == "" {
		if credential == nil {
			if !accountAuthType.Credential.Verified {
				message, credData, err := a.beginRegistration(auth, user)
				if err != nil {
					return "", errors.WrapErrorAction(logutils.ActionStart, "registration", nil, err)
				}

				accountAuthType.Credential.Value = credData
				err = a.auth.storage.UpdateCredential(nil, accountAuthType.Credential)
				if err != nil {
					return "", errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
				}

				return message, nil
			}
			return "", errors.ErrorData(logutils.StatusMissing, model.TypeCredential, nil)
		}
		return a.beginLogin(auth, accountAuthType, user, l)
	}

	sessionJSON, ok := accountAuthType.Credential.Value["session"].(string)
	if !ok {
		return "", errors.ErrorData(logutils.StatusInvalid, "session param", nil)
	}

	var session webauthn.SessionData
	err = json.Unmarshal([]byte(sessionJSON), &session)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, "session", nil, err)
	}

	if credential == nil {
		err = a.completeRegistration(auth, session, accountAuthType, parsedCreds.Response, user, l)
		if err != nil {
			return "", err
		}
		return "registration complete", nil
	}

	return "", a.completeLogin(auth, session, accountAuthType, parsedCreds.Response, user, l)
}

func (a *webAuthnAuthImpl) beginRegistration(auth *webauthn.WebAuthn, user webAuthnUser) (string, map[string]interface{}, error) {
	if user.DisplayName == "" {
		user.DisplayName = user.Name
	}

	options, session, err := auth.BeginRegistration(user)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAccount, nil, err)
	}

	sessionData, err := json.Marshal(session)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionMarshal, "session", nil, err)
	}

	credData := map[string]interface{}{
		"session": string(sessionData),
	}

	optionData, err := json.Marshal(options)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionMarshal, "creation options", nil, err)
	}

	return string(optionData), credData, nil
}

func (a *webAuthnAuthImpl) completeRegistration(auth *webauthn.WebAuthn, session webauthn.SessionData,
	accountAuthType model.AccountAuthType, creds string, user webAuthnUser, l *logs.Log) error {
	response, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(creds))
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionParse, "cred create response", nil, err)
	}

	credential, err := auth.CreateCredential(user, session, response)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCreate, model.TypeCredential, nil, err)
	}

	credentialData, err := json.Marshal(credential)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionMarshal, "credential", nil, err)
	}

	accountAuthType.Credential.Value = map[string]interface{}{
		"credential": string(credentialData),
	}
	accountAuthType.Credential.Verified = true
	err = a.auth.storage.UpdateCredential(nil, accountAuthType.Credential)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
	}

	return nil
}

func (a *webAuthnAuthImpl) beginLogin(auth *webauthn.WebAuthn, accountAuthType model.AccountAuthType, user webAuthnUser, l *logs.Log) (string, error) {
	options, session, err := auth.BeginLogin(user)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionStart, "login", nil, err)
	}

	sessionData, err := json.Marshal(session)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionMarshal, "session", nil, err)
	}

	accountAuthType.Credential.Value["session"] = string(sessionData)
	err = a.auth.storage.UpdateCredential(nil, accountAuthType.Credential)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
	}

	optionData, err := json.Marshal(options)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionMarshal, "creation options", nil, err)
	}

	return string(optionData), nil
}

func (a *webAuthnAuthImpl) completeLogin(auth *webauthn.WebAuthn, session webauthn.SessionData,
	accountAuthType model.AccountAuthType, creds string, user webAuthnUser, l *logs.Log) error {
	response, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(creds))
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionParse, "cred request response", nil, err)
	}

	newCred, err := auth.ValidateLogin(user, session, response)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionValidate, "login", nil, err)
	}

	credentialData, err := json.Marshal(newCred)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionMarshal, "credential", nil, err)
	}

	accountAuthType.Credential.Value = map[string]interface{}{
		"credential": string(credentialData),
	}
	accountAuthType.Credential.Verified = true
	err = a.auth.storage.UpdateCredential(nil, accountAuthType.Credential)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
	}
	return nil
}

func (a *webAuthnAuthImpl) signUpAdmin(identifierImpl identifierType, appName string, creds authCreds, newCredentialID string) (map[string]interface{}, map[string]interface{}, error) {
	return nil, nil, nil
}

func (a *webAuthnAuthImpl) forgotCredential(identifierImpl identifierType, credential authCreds, appName string, credID string) (map[string]interface{}, error) {
	return nil, nil
}

func (a *webAuthnAuthImpl) resetCredential(credential authCreds, resetCode *string, params string) (map[string]interface{}, error) {
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
