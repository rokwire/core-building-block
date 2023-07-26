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
	"bytes"
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
	credentialKeyCredential string = "credential"

	stateKeyChallenge string = "challenge"
	stateKeySession   string = "session"

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
	Credential *string `json:"credential,omitempty"`
	Response   *string `json:"response,omitempty"`
}

func (c *webauthnCreds) getCredential(key string) string {
	switch key {
	case credentialKeyResponse:
		if c.Response != nil {
			return *c.Response
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

func (a *webAuthnAuthImpl) signUp(identifierImpl identifierType, appOrg model.ApplicationOrganization, creds string, params string, config map[string]interface{}) (string, *model.AccountIdentifier, *model.Credential, error) {
	auth, err := buildWebAuthn(config, appOrg.Application.Name)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionInitialize, logutils.MessageDataType(AuthTypeWebAuthn), nil, err)
	}

	parameters, err := a.parseParams(params)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionParse, typeWebAuthnParams, nil, err)
	}

	displayName := ""
	if parameters.DisplayName != nil {
		displayName = *parameters.DisplayName
	}

	user := webAuthnUser{ID: uuid.NewString(), DisplayName: displayName}
	return a.beginRegistration(identifierImpl, auth, user, appOrg)
}

func (a *webAuthnAuthImpl) checkCredentials(identifierImpl identifierType, accountIdentifier *model.AccountIdentifier, credentials []model.Credential, creds string, displayName string, appOrg model.ApplicationOrganization, config map[string]interface{}) (string, string, error) {
	if len(credentials) == 0 {
		return "", "", errors.ErrorData(logutils.StatusMissing, model.TypeCredential, nil)
	}

	auth, err := buildWebAuthn(config, appOrg.Application.Name)
	if err != nil {
		return "", "", errors.WrapErrorAction(logutils.ActionInitialize, logutils.MessageDataType(AuthTypeWebAuthn), nil, err)
	}

	incomingCreds, err := a.parseCreds(creds)
	if err != nil {
		return "", "", errors.WrapErrorAction(logutils.ActionParse, typeWebAuthnCreds, nil, err)
	}

	var user webauthn.User
	response := incomingCreds.getCredential(credentialKeyResponse)
	if response == "" {
		for _, credential := range credentials {
			webAuthnCred, err := a.parseWebAuthnCredential(credential.Value)
			if err != nil {
				return "", "", errors.WrapErrorAction(logutils.ActionParse, "webauthn credential", nil, err)
			}

			// have at least one valid webauthn credential, so initiate login
			if webAuthnCred != nil {
				if accountIdentifier != nil {
					if !accountIdentifier.Verified {
						return "", "", errors.ErrorData(logutils.StatusInvalid, model.TypeAccountIdentifier, &logutils.FieldArgs{"verified": false})
					}
					user = webAuthnUser{ID: accountIdentifier.Account.ID, DisplayName: displayName}
				}

				optionData, err := a.beginLogin(auth, user, appOrg)
				return optionData, "", err
			}
		}

		return "", "", errors.ErrorData(logutils.StatusMissing, model.TypeCredential, nil)

		//TODO: should we register new credential if no valid credentials are found?
		// var message string
		// message, accountIdentifier, storedCreds.Value, _, err = a.beginRegistration(identifierImpl, auth, user, appName)
		// if err != nil {
		// 	return "", errors.WrapErrorAction(logutils.ActionStart, "registration", nil, err)
		// }

		// err = a.auth.storage.UpdateCredential(nil, storedCreds)
		// if err != nil {
		// 	return "", errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
		// }

		// return message, nil
	}
	if !accountIdentifier.Verified {
		return "", "", errors.ErrorData(logutils.StatusInvalid, model.TypeAccountIdentifier, &logutils.FieldArgs{"verified": false})
	}

	if accountIdentifier != nil {
		user = webAuthnUser{ID: accountIdentifier.Account.ID, DisplayName: displayName}

		// complete registration
		if response, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(creds)); err == nil {
			credID, err := a.completeRegistration(auth, response, user, appOrg)
			if err != nil {
				return "", "", err
			}
			return "registration complete", credID, nil
		}
	}

	// either complete login with identifier or complete discoverable login without identifier
	if response, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(creds)); err == nil {
		credID, err := a.completeLogin(auth, response, user, credentials, appOrg)
		return "", credID, err
	}

	// cannot parse response, so it is invalid
	return "", "", errors.ErrorData(logutils.StatusInvalid, logutils.MessageDataType(credentialKeyResponse), nil)
}

func (a *webAuthnAuthImpl) beginRegistration(identifierImpl identifierType, auth *webauthn.WebAuthn, user webAuthnUser, appOrg model.ApplicationOrganization) (string, *model.AccountIdentifier, *model.Credential, error) {
	identifier, err := identifierImpl.getUserIdentifier("")
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionGet, "identifier", nil, err)
	}

	if user.DisplayName == "" {
		user.DisplayName = identifier
	}

	options, session, err := auth.BeginRegistration(user)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAccount, nil, err)
	}

	accountIdentifier := model.AccountIdentifier{ID: uuid.NewString(), Code: identifierImpl.getCode(), Identifier: identifier,
		Account: model.Account{ID: user.ID}, DateCreated: time.Now().UTC()}
	sent := false
	if identifierChannel, ok := identifierImpl.(authCommunicationChannel); ok {
		sent, err = identifierChannel.sendVerifyIdentifier(&accountIdentifier, appOrg.Application.Name)
		if err != nil {
			return "", nil, nil, errors.WrapErrorAction(logutils.ActionSend, "identifier verification", nil, err)
		}
	}
	accountIdentifier.Verified = !sent

	sessionData, err := json.Marshal(session)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionMarshal, "session", nil, err)
	}

	state := map[string]interface{}{stateKeyChallenge: session.Challenge, stateKeySession: string(sessionData)}
	loginState := model.LoginState{ID: uuid.NewString(), AppID: appOrg.Application.ID, OrgID: appOrg.Organization.ID, AccountID: &user.ID, State: state, DateCreated: time.Now().UTC()}
	err = a.auth.storage.InsertLoginState(loginState)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionCreate, model.TypeLoginState, nil, err)
	}

	optionData, err := json.Marshal(options)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionMarshal, "creation options", nil, err)
	}

	return string(optionData), &accountIdentifier, nil, nil
}

func (a *webAuthnAuthImpl) completeRegistration(auth *webauthn.WebAuthn, response *protocol.ParsedCredentialCreationData, user webauthn.User, appOrg model.ApplicationOrganization) (string, error) {
	var accountID *string
	if user != nil {
		accountIDVal := string(user.WebAuthnID())
		accountID = &accountIDVal
	}

	params := map[string]interface{}{
		stateKeyChallenge: response.Response.CollectedClientData.Challenge,
	}
	loginState, err := a.auth.storage.FindLoginState(appOrg.Application.ID, appOrg.Organization.ID, accountID, params)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionFind, model.TypeLoginState, nil, err)
	}

	session, err := a.parseWebAuthnSession(loginState.State)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionParse, "session", nil, err)
	}
	if session == nil {
		return "", errors.ErrorData(logutils.StatusMissing, "session", nil)
	}

	credential, err := auth.CreateCredential(user, *session, response)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionCreate, model.TypeCredential, nil, err)
	}

	credentialData, err := json.Marshal(credential)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionMarshal, "credential", nil, err)
	}

	credentialStr := string(credentialData)
	credValue := &webauthnCreds{Credential: &credentialStr}
	credData, err := credValue.toMap()
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionCast, "map from webauthn creds", nil, err)
	}

	storeCred := &model.Credential{ID: uuid.NewString(), Value: credData, AuthType: model.AuthType{Code: a.authType}, DateCreated: time.Now().UTC()}
	err = a.auth.storage.InsertCredential(nil, storeCred)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
	}

	return storeCred.ID, nil
}

func (a *webAuthnAuthImpl) beginLogin(auth *webauthn.WebAuthn, user webauthn.User, appOrg model.ApplicationOrganization) (string, error) {
	var options *protocol.CredentialAssertion
	var session *webauthn.SessionData
	var err error
	var accountID *string
	if user != nil {
		options, session, err = auth.BeginLogin(user)
		if err != nil {
			return "", errors.WrapErrorAction(logutils.ActionStart, "login", nil, err)
		}
		accountIDVal := string(user.WebAuthnID())
		accountID = &accountIDVal
	} else {
		// if no user, we can start a discoverable login
		options, session, err = auth.BeginDiscoverableLogin()
		if err != nil {
			return "", errors.WrapErrorAction(logutils.ActionStart, "discoverable login", nil, err)
		}
	}

	sessionData, err := json.Marshal(session)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionMarshal, "session", nil, err)
	}

	state := map[string]interface{}{stateKeyChallenge: session.Challenge, stateKeySession: string(sessionData)}
	loginState := model.LoginState{ID: uuid.NewString(), AppID: appOrg.Application.ID, OrgID: appOrg.Organization.ID, AccountID: accountID, State: state, DateCreated: time.Now().UTC()}
	err = a.auth.storage.InsertLoginState(loginState)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
	}

	optionData, err := json.Marshal(options)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionMarshal, "creation options", nil, err)
	}

	return string(optionData), nil
}

func (a *webAuthnAuthImpl) completeLogin(auth *webauthn.WebAuthn, response *protocol.ParsedCredentialAssertionData, user webauthn.User, credentials []model.Credential, appOrg model.ApplicationOrganization) (string, error) {
	var accountID *string
	if user != nil {
		accountIDVal := string(user.WebAuthnID())
		accountID = &accountIDVal
	}

	params := map[string]interface{}{
		stateKeyChallenge: response.Response.CollectedClientData.Challenge,
	}
	loginState, err := a.auth.storage.FindLoginState(appOrg.Application.ID, appOrg.Organization.ID, accountID, params)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionFind, model.TypeLoginState, nil, err)
	}

	session, err := a.parseWebAuthnSession(loginState.State)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionParse, "session", nil, err)
	}
	if session == nil {
		return "", errors.ErrorData(logutils.StatusMissing, "session", nil)
	}

	var credential *model.Credential
	var updatedCred *webauthn.Credential
	if user != nil {
		updatedCred, err = auth.ValidateLogin(user, *session, response)
		if err != nil {
			return "", errors.WrapErrorAction(logutils.ActionValidate, "login", nil, err)
		}

		// find matching credential in provided list
		for _, cred := range credentials {
			webAuthnCred, err := a.parseWebAuthnCredential(cred.Value)
			if err != nil {
				return "", errors.WrapErrorAction(logutils.ActionParse, "webauthn credential", nil, err)
			}

			if webAuthnCred != nil && bytes.Equal(updatedCred.ID, webAuthnCred.ID) {
				credential = &cred
				break
			}
		}
	} else {
		// if no user, we can validate a discoverable login
		userDiscoverer := func(rawID, userHandle []byte) (webauthn.User, error) {
			// find account by userHandle (should match an account ID)
			account, err := a.auth.storage.FindAccountByID(nil, string(userHandle))
			if err != nil {
				return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, &logutils.FieldArgs{"userHandle": string(userHandle)}, err)
			}
			if account == nil {
				return nil, errors.ErrorData(logutils.StatusMissing, model.TypeAccount, &logutils.FieldArgs{"userHandle": string(userHandle)})
			}

			// find matching credential by rawId (should match a credential ID)
			for _, aat := range account.GetAccountAuthTypes(a.authType) {
				if aat.Credential != nil {
					webAuthnCred, err := a.parseWebAuthnCredential(aat.Credential.Value)
					if err != nil {
						return nil, errors.WrapErrorAction(logutils.ActionParse, "webauthn credential", nil, err)
					}

					if webAuthnCred != nil && bytes.Equal(rawID, webAuthnCred.ID) {
						credential = aat.Credential
						return webAuthnUser{ID: account.ID}, nil
					}
				}
			}

			return nil, errors.ErrorData(logutils.StatusMissing, "user", &logutils.FieldArgs{"userHandle": string(userHandle), "rawID": string(rawID)})
		}

		updatedCred, err = auth.ValidateDiscoverableLogin(userDiscoverer, *session, response)
		if err != nil {
			return "", errors.WrapErrorAction(logutils.ActionValidate, "discoverable login", nil, err)
		}
	}

	credID := ""
	if credential != nil {
		credID = credential.ID
		credentialData, err := json.Marshal(updatedCred)
		if err != nil {
			return "", errors.WrapErrorAction(logutils.ActionMarshal, "credential", nil, err)
		}

		credential.Value[credentialKeyCredential] = string(credentialData)
		err = a.auth.storage.UpdateCredential(nil, credential)
		if err != nil {
			return "", errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
		}
	}

	return credID, nil
}

func (a *webAuthnAuthImpl) signUpAdmin(identifierImpl identifierType, appOrg model.ApplicationOrganization, creds string) (map[string]interface{}, *model.AccountIdentifier, *model.Credential, error) {
	return nil, nil, nil, errors.New(logutils.Unimplemented)
}

func (a *webAuthnAuthImpl) forgotCredential(identifierImpl identifierType, credential *model.Credential, appOrg model.ApplicationOrganization) (map[string]interface{}, error) {
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

func (a *webAuthnAuthImpl) parseWebAuthnSession(credValue map[string]interface{}) (*webauthn.SessionData, error) {
	if credValue[stateKeySession] == nil {
		return nil, nil
	}

	sessionJSON, ok := credValue[stateKeySession].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusInvalid, "session", nil)
	}

	var session webauthn.SessionData
	err := json.Unmarshal([]byte(sessionJSON), &session)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, "session", nil, err)
	}

	return &session, nil
}

func (a *webAuthnAuthImpl) parseWebAuthnCredential(credValue map[string]interface{}) (*webauthn.Credential, error) {
	if credValue[credentialKeyCredential] == nil {
		return nil, nil
	}

	credentialJSON, ok := credValue[credentialKeyCredential].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusInvalid, "credential", nil)
	}

	var credentialVal webauthn.Credential
	err := json.Unmarshal([]byte(credentialJSON), &credentialVal)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, "credential", nil, err)
	}

	return &credentialVal, nil
	// user.Credentials = []webauthn.Credential{credentialVal}
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
