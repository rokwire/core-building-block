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
	"github.com/rokwire/logging-library-go/v2/logutils"
)

const (
	//AuthTypeWebAuthn webauthn auth type
	AuthTypeWebAuthn string = "webauthn"

	typeWebAuthnCreds  logutils.MessageDataType = "webauthn creds"
	typeWebAuthnParams logutils.MessageDataType = "webauthn params"
)

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

// WebAuthnName unique human-readable identifier
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

func buildWebAuthn(config map[string]interface{}, appName string) (*webauthn.WebAuthn, error) {
	rpID, ok := config["rp_id"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusInvalid, "supported auth type param", &logutils.FieldArgs{"param": "rp_id", "app_name": appName})
	}
	rpOrigins, ok := config["rp_origins"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusInvalid, "supported auth type param", &logutils.FieldArgs{"param": "rp_origins", "app_name": appName})
	}

	requireResidentKey, _ := config["require_resident_key"].(bool)
	residentKey, ok := config["resident_key"].(string)
	if !ok {
		residentKey = string(protocol.ResidentKeyRequirementRequired)
	}
	userVerification, ok := config["user_verification"].(string)
	if !ok {
		userVerification = string(protocol.VerificationRequired)
	}
	attestationPreference, ok := config["attestation_preference"].(string)
	if !ok {
		attestationPreference = string(protocol.PreferNoAttestation)
	}
	authenticatorAttachment, ok := config["authenticator_attachment"].(string)
	if !ok {
		authenticatorAttachment = string(protocol.Platform)
	}

	wconfig := &webauthn.Config{
		RPDisplayName:         appName,                       // Display Name for your site
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

func (a *webAuthnAuthImpl) signUp(identifierImpl identifierType, appName string, creds authCreds, params string, config map[string]interface{}, newCredentialID string) (string, map[string]interface{}, error) {
	auth, err := buildWebAuthn(config, appName)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionInitialize, logutils.MessageDataType(AuthTypeWebAuthn), nil, err)
	}

	if creds.identifier() == "" {
		return "", nil, errors.ErrorData(logutils.StatusMissing, "identifier", nil)
	}
	identifier := strings.TrimSpace(strings.ToLower(creds.identifier()))

	passkeyParams, err := identifierImpl.parseParams(params)
	if err != nil {
		return "", nil, errors.ErrorData(logutils.StatusInvalid, "webauthn params", nil)
	}
	paramType, parameter := passkeyParams.parameter()
	if paramType != AuthTypeWebAuthn {
		return "", nil, errors.ErrorData(logutils.StatusInvalid, typeWebAuthnParams, nil)
	}

	user := webAuthnUser{ID: newCredentialID, Name: identifier, DisplayName: parameter}
	return a.beginRegistration(auth, user)
}

func (a *webAuthnAuthImpl) checkCredential(identifierImpl identifierType, storedCreds *model.Credential, incomingCreds authCreds, displayName string, appName string, config map[string]interface{}) (string, error) {
	if storedCreds == nil {
		return "", errors.ErrorData(logutils.StatusMissing, model.TypeCredential, nil)
	}
	if storedCreds.Value == nil {
		return "", errors.ErrorData(logutils.StatusInvalid, model.TypeCredential, logutils.StringArgs(storedCreds.ID))
	}

	auth, err := buildWebAuthn(config, appName)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionInitialize, logutils.MessageDataType(AuthTypeWebAuthn), nil, err)
	}

	user := webAuthnUser{ID: storedCreds.ID, Name: incomingCreds.identifier(), DisplayName: displayName}

	var credential *webauthn.Credential
	if storedCreds.Value["credential"] != nil {
		credentialJSON, ok := storedCreds.Value["credential"].(string)
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

	_, response := incomingCreds.getCredential()
	if response == "" {
		if credential == nil {
			if !storedCreds.Verified {
				message, credData, err := a.beginRegistration(auth, user)
				if err != nil {
					return "", errors.WrapErrorAction(logutils.ActionStart, "registration", nil, err)
				}

				storedCreds.Value = credData
				err = a.auth.storage.UpdateCredential(nil, storedCreds)
				if err != nil {
					return "", errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
				}

				return message, nil
			}
			return "", errors.ErrorData(logutils.StatusMissing, model.TypeCredential, nil)
		}
		return a.beginLogin(auth, storedCreds, user)
	}

	sessionJSON, ok := storedCreds.Value["session"].(string)
	if !ok {
		return "", errors.ErrorData(logutils.StatusInvalid, "session param", nil)
	}

	var session webauthn.SessionData
	err = json.Unmarshal([]byte(sessionJSON), &session)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, "session", nil, err)
	}

	if credential == nil {
		err = a.completeRegistration(auth, session, storedCreds, response, user)
		if err != nil {
			return "", err
		}
		return "registration complete", nil
	}

	return "", a.completeLogin(auth, session, storedCreds, response, user)
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
	storedCreds *model.Credential, creds string, user webAuthnUser) error {
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

	storedCreds.Value = map[string]interface{}{
		"credential": string(credentialData),
	}
	storedCreds.Verified = true
	err = a.auth.storage.UpdateCredential(nil, storedCreds)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
	}

	return nil
}

func (a *webAuthnAuthImpl) beginLogin(auth *webauthn.WebAuthn, storedCreds *model.Credential, user webAuthnUser) (string, error) {
	options, session, err := auth.BeginLogin(user)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionStart, "login", nil, err)
	}

	sessionData, err := json.Marshal(session)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionMarshal, "session", nil, err)
	}

	storedCreds.Value["session"] = string(sessionData)
	err = a.auth.storage.UpdateCredential(nil, storedCreds)
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
	storedCreds *model.Credential, creds string, user webAuthnUser) error {
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

	storedCreds.Value = map[string]interface{}{
		"credential": string(credentialData),
	}
	storedCreds.Verified = true
	err = a.auth.storage.UpdateCredential(nil, storedCreds)
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

// initWebAuthnAuth initializes and registers a new webauthn auth instance
func initWebAuthnAuth(auth *Auth) (*webAuthnAuthImpl, error) {
	webauthn := &webAuthnAuthImpl{auth: auth, authType: AuthTypeWebAuthn}

	err := auth.registerAuthType(webauthn.authType, webauthn)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAuthType, logutils.StringArgs(AuthTypeWebAuthn), err)
	}

	return webauthn, nil
}
