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
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"gopkg.in/go-playground/validator.v9"

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

const (
	//AuthTypeWebAuthn webauthn auth type
	AuthTypeWebAuthn string = "webauthn"

	credentialKeyResponse   string = "response"
	credentialKeySession    string = "session"
	credentialKeyCredential string = "credential"

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

// webauthnCreds represents the creds struct for webauthn authentication
type webauthnCreds struct {
	Session    *string `json:"session,omitempty"`
	Credential *string `json:"credential,omitempty"`
	Response   *string `json:"response,omitempty"`
}

func (c *webauthnCreds) getCredential(key string) string {
	switch key {
	case credentialKeyResponse:
		if c.Response != nil {
			return *c.Response
		}
	case credentialKeySession:
		if c.Session != nil {
			return *c.Session
		}
	case credentialKeyCredential:
		if c.Credential != nil {
			return *c.Credential
		}
	}
	return ""
}

func (c *webauthnCreds) setCredential(value string, key string) {
	switch key {
	case credentialKeyResponse:
		c.Response = &value
	case credentialKeySession:
		c.Session = &value
	case credentialKeyCredential:
		c.Credential = &value
	}
}

func (c *webauthnCreds) getResetParams() (*string, *time.Time) {
	return nil, nil
}

func (c *webauthnCreds) setResetParams(code *string, expiry *time.Time) {}

func (c *webauthnCreds) toMap() (map[string]interface{}, error) {
	credBytes, err := json.Marshal(c)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typeWebAuthnCreds, nil, err)
	}
	var credsMap map[string]interface{}
	err = json.Unmarshal(credBytes, &credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, "webauthn creds map", nil, err)
	}
	return credsMap, nil
}

type webauthnParams struct {
	DisplayName *string `json:"display_name"`
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

func (a *webAuthnAuthImpl) signUp(identifierImpl identifierType, appName string, creds string, params string, config map[string]interface{}, newCredentialID string) (string, *model.AccountIdentifier, map[string]interface{}, bool, error) {
	auth, err := buildWebAuthn(config, appName)
	if err != nil {
		return "", nil, nil, false, errors.WrapErrorAction(logutils.ActionInitialize, logutils.MessageDataType(AuthTypeWebAuthn), nil, err)
	}

	identifier, err := identifierImpl.getUserIdentifier(creds)
	if err != nil {
		return "", nil, nil, false, errors.WrapErrorAction(logutils.ActionGet, "identifier", nil, err)
	}

	parameters, err := a.parseParams(params)
	if err != nil {
		return "", nil, nil, false, errors.WrapErrorAction(logutils.ActionParse, typeWebAuthnParams, nil, err)
	}

	displayName := ""
	if parameters.DisplayName != nil {
		displayName = *parameters.DisplayName
	}

	user := webAuthnUser{ID: newCredentialID, Name: identifier, DisplayName: displayName}
	return a.beginRegistration(identifierImpl, auth, user, appName)
}

func (a *webAuthnAuthImpl) checkCredential(identifierImpl identifierType, accountIdentifier *model.AccountIdentifier, credentials []model.Credential, creds string, displayName string, appName string, config map[string]interface{}) (string, error) {
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

	identifier, err := identifierImpl.getUserIdentifier(creds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionGet, "identifier", nil, err)
	}

	user := webAuthnUser{ID: storedCreds.ID, Name: identifier, DisplayName: displayName}

	credentials, err := a.parseCreds(creds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionParse, typeWebAuthnCreds, nil, err)
	}

	var credential *webauthn.Credential
	if storedCreds.Value[credentialKeyCredential] != nil {
		credentialJSON, ok := storedCreds.Value[credentialKeyCredential].(string)
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

	response := credentials.getCredential(credentialKeyResponse)
	if response == "" {
		if credential == nil {
			if accountIdentifier == nil || !accountIdentifier.Verified {
				var message string
				message, accountIdentifier, storedCreds.Value, _, err = a.beginRegistration(identifierImpl, auth, user, appName)
				if err != nil {
					return "", errors.WrapErrorAction(logutils.ActionStart, "registration", nil, err)
				}

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

	sessionJSON, ok := storedCreds.Value[credentialKeySession].(string)
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

func (a *webAuthnAuthImpl) beginRegistration(identifierImpl identifierType, auth *webauthn.WebAuthn, user webAuthnUser, appName string) (string, *model.AccountIdentifier, map[string]interface{}, bool, error) {
	if user.DisplayName == "" {
		user.DisplayName = user.Name
	}

	options, session, err := auth.BeginRegistration(user)
	if err != nil {
		return "", nil, nil, false, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAccount, nil, err)
	}

	sessionData, err := json.Marshal(session)
	if err != nil {
		return "", nil, nil, false, errors.WrapErrorAction(logutils.ActionMarshal, "session", nil, err)
	}
	sessionStr := string(sessionData)
	credValue := &webauthnCreds{Session: &sessionStr}

	accountIdentifier := model.AccountIdentifier{ID: uuid.NewString(), Code: identifierImpl.getCode(), Identifier: user.Name, DateCreated: time.Now().UTC()}
	sent := false
	if identifierChannel, ok := identifierImpl.(authCommunicationChannel); ok {
		sent, err = identifierChannel.sendVerifyIdentifier(&accountIdentifier, appName)
		if err != nil {
			return "", nil, nil, false, errors.WrapErrorAction(logutils.ActionSend, "identifier verification", nil, err)
		}
	} else {
		accountIdentifier.Verified = true
	}
	credData, err := credValue.toMap()
	if err != nil {
		return "", nil, nil, false, errors.WrapErrorAction(logutils.ActionCast, "map from creds", nil, err)
	}

	optionData, err := json.Marshal(options)
	if err != nil {
		return "", nil, nil, false, errors.WrapErrorAction(logutils.ActionMarshal, "creation options", nil, err)
	}

	return string(optionData), &accountIdentifier, credData, !sent, nil
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

	storedCreds.Value[credentialKeyCredential] = string(credentialData)
	storedCreds.Value[credentialKeySession] = nil

	err = a.auth.storage.UpdateCredential(nil, storedCreds)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
	}

	return nil
}

func (a *webAuthnAuthImpl) beginLogin(auth *webauthn.WebAuthn, credentials []model.Credential, user webAuthnUser) (string, error) {
	options, session, err := auth.BeginLogin(user)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionStart, "login", nil, err)
	}

	sessionData, err := json.Marshal(session)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionMarshal, "session", nil, err)
	}

	storedCreds.Value[credentialKeySession] = string(sessionData)
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

	storedCreds.Value[credentialKeyCredential] = string(credentialData)
	storedCreds.Value[credentialKeySession] = nil
	err = a.auth.storage.UpdateCredential(nil, storedCreds)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
	}
	return nil
}

func (a *webAuthnAuthImpl) signUpAdmin(identifierImpl identifierType, appName string, creds string, newCredentialID string) (*model.AccountIdentifier, map[string]interface{}, map[string]interface{}, error) {
	return nil, nil, nil, errors.New(logutils.Unimplemented)
}

func (a *webAuthnAuthImpl) forgotCredential(identifierImpl identifierType, credential *model.Credential, appName string) (map[string]interface{}, error) {
	//TODO: implement
	return nil, errors.New(logutils.Unimplemented)
}

func (a *webAuthnAuthImpl) resetCredential(credential *model.Credential, resetCode *string, params string) (map[string]interface{}, error) {
	//TODO: implement
	return nil, errors.New(logutils.Unimplemented)
}

// Helpers

func (a *webAuthnAuthImpl) parseCreds(creds string) (*webauthnCreds, error) {
	var credential webauthnCreds
	err := json.Unmarshal([]byte(creds), &credential)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeWebAuthnCreds, nil, err)
	}
	err = validator.New().Struct(credential)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, typeWebAuthnCreds, nil, err)
	}
	return &credential, nil
}

func (a *webAuthnAuthImpl) parseParams(params string) (*webauthnParams, error) {
	var parameters webauthnParams
	err := json.Unmarshal([]byte(params), &parameters)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeWebAuthnParams, nil, err)
	}
	err = validator.New().Struct(parameters)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, typeWebAuthnParams, nil, err)
	}
	return &parameters, nil
}

func (a *webAuthnAuthImpl) mapToCreds(credsMap map[string]interface{}) (*webauthnCreds, error) {
	credBytes, err := json.Marshal(credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, "webauthn creds map", nil, err)
	}
	var creds webauthnCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeWebAuthnCreds, nil, err)
	}

	err = validator.New().Struct(creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, typeWebAuthnCreds, nil, err)
	}
	return &creds, nil
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
