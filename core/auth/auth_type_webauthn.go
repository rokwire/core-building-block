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
	"core-building-block/driven/storage"
	"core-building-block/utils"
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

	rpDisplayNameKey string = "rp_display_name"
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

func (c *webauthnCreds) toMap() (map[string]interface{}, error) {
	if c == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, typeWebAuthnCreds, nil)
	}

	credsMap, err := utils.JSONConvert[map[string]interface{}, webauthnCreds](*c)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionParse, typeWebAuthnCreds, nil, err)
	}
	if credsMap == nil {
		return nil, errors.ErrorData(logutils.StatusInvalid, "webauthn creds map", nil)
	}
	return *credsMap, nil
}

type webauthnParams struct {
	DisplayName *string `json:"display_name"`
}

// WebAuthn implementation of authType
type webAuthnAuthImpl struct {
	auth     *Auth
	authType string

	config *webauthn.WebAuthn
}

func (a *webAuthnAuthImpl) signUp(identifierImpl identifierType, accountID *string, appOrg model.ApplicationOrganization, creds string, params string) (string, *model.AccountIdentifier, *model.Credential, error) {
	parameters, err := a.parseParams(params)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionParse, typeWebAuthnParams, nil, err)
	}

	var user webAuthnUser
	if identifierImpl != nil {
		user.Name = identifierImpl.getIdentifier()
	} else if parameters.DisplayName != nil {
		user.Name = *parameters.DisplayName
	}

	var accountIdentifier *model.AccountIdentifier
	if accountID != nil {
		// we are linking a webauthn credential, so use the existing accountID
		user.ID = *accountID
	} else {
		_, accountIdentifier, err = identifierImpl.buildIdentifier(nil, appOrg.Application.Name)
		if err != nil {
			return "", nil, nil, errors.WrapErrorAction("building", "identifier", logutils.StringArgs(identifierImpl.getCode()), err)
		}

		accountIdentifier.Verified = false
		user.ID = accountIdentifier.Account.ID
	}

	if parameters.DisplayName != nil {
		user.DisplayName = *parameters.DisplayName
	} else if accountIdentifier != nil {
		user.DisplayName = accountIdentifier.Identifier
	}

	message, err := a.beginRegistration(user, appOrg)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionStart, "webauthn registration", nil, err)
	}

	return message, accountIdentifier, nil, nil
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

func (a *webAuthnAuthImpl) checkCredentials(identifierImpl identifierType, accountID *string, aats []model.AccountAuthType, creds string, params string, appOrg model.ApplicationOrganization) (string, string, error) {
	incomingCreds, err := a.parseCreds(creds)
	if err != nil {
		return "", "", errors.WrapErrorAction(logutils.ActionParse, typeWebAuthnCreds, nil, err)
	}

	var user webauthn.User
	if incomingCreds.Response == nil {
		user, err = a.buildUser(accountID, aats)
		if err != nil {
			return "", "", errors.WrapErrorAction("building", "webauthn user", nil, err)
		}

		var optionData string
		if user != nil {
			// attempting login with identifier and no credentials - need to restart registration instead
			parameters, err := a.parseParams(params)
			if err != nil {
				return "", "", errors.WrapErrorAction(logutils.ActionParse, typeWebAuthnParams, nil, err)
			}

			namedUser, ok := user.(webAuthnUser)
			if !ok {
				return "", "", errors.ErrorData(logutils.StatusInvalid, "webauthn user", nil)
			}

			if identifierImpl != nil {
				namedUser.Name = identifierImpl.getIdentifier()
			} else if parameters.DisplayName != nil {
				namedUser.Name = *parameters.DisplayName
			}

			if parameters.DisplayName != nil {
				namedUser.DisplayName = *parameters.DisplayName
			} else if identifierImpl != nil {
				namedUser.DisplayName = identifierImpl.getIdentifier()
			}

			user = namedUser
			if len(user.WebAuthnCredentials()) == 0 {
				optionData, err = a.beginRegistration(user, appOrg)
				if err != nil {
					return "", "", errors.WrapErrorAction(logutils.ActionStart, "webauthn registration", nil, err)
				}

				return optionData, "", nil
			}
		}

		optionData, err = a.beginLogin(user, appOrg)
		if err != nil {
			return "", "", errors.WrapErrorAction("beginning", "webauthn login", nil, err)
		}

		return optionData, "", nil
	}

	// accountID will not be nil if linking or if account identifier has been verified during sign up
	if accountID != nil {
		user, err = a.buildUser(accountID, aats)
		if err != nil {
			return "", "", errors.WrapErrorAction("building", "webauthn user", nil, err)
		}

		// complete registration
		if response, err := protocol.ParseCredentialCreationResponseBody(strings.NewReader(*incomingCreds.Response)); err == nil {
			credID, err := a.completeRegistration(response, user, aats, appOrg)
			if err != nil {
				return "", "", err
			}
			return "", credID, nil
		}
	}

	// either complete login with identifier or complete discoverable login without identifier
	if response, err := protocol.ParseCredentialRequestResponseBody(strings.NewReader(*incomingCreds.Response)); err == nil {
		if user != nil {
			if len(response.Response.UserHandle) > 0 {
				for _, aat := range aats {
					// backwards compatibility: user handles (user IDs) used to be credential IDs
					// check if the user handle matches any of the user's webauthn credential IDs
					// if so, set the user handle equal to the user ID (now the account ID)
					if aat.Credential != nil && bytes.Equal(response.Response.UserHandle, []byte(aat.Credential.ID)) {
						response.Response.UserHandle = user.WebAuthnID()
						break
					}
				}
			}
		}

		credID, err := a.completeLogin(response, user, aats, appOrg)
		return "", credID, err
	}

	// cannot parse response, so it is invalid
	return "", "", errors.ErrorData(logutils.StatusInvalid, logutils.MessageDataType(credentialKeyResponse), nil)
}

func (a *webAuthnAuthImpl) withParams(params map[string]interface{}) (authType, error) {
	rpDisplayName, _ := params["rp_display_name"].(string)
	if rpDisplayName == "" {
		rpDisplayName = rpDisplayNameKey
	}
	rpID, ok := params["rp_id"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusInvalid, "supported auth type param", &logutils.FieldArgs{"param": "rp_id"})
	}
	rpOrigins, ok := params["rp_origins"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusInvalid, "supported auth type param", &logutils.FieldArgs{"param": "rp_origins"})
	}

	requireResidentKey, _ := params["require_resident_key"].(bool)
	residentKey, ok := params["resident_key"].(string)
	if !ok {
		residentKey = string(protocol.ResidentKeyRequirementRequired)
	}
	userVerification, ok := params["user_verification"].(string)
	if !ok {
		userVerification = string(protocol.VerificationRequired)
	}
	attestationPreference, ok := params["attestation_preference"].(string)
	if !ok {
		attestationPreference = string(protocol.PreferNoAttestation)
	}
	authenticatorAttachment, ok := params["authenticator_attachment"].(string)
	if !ok {
		authenticatorAttachment = string(protocol.Platform)
	}

	wconfig := &webauthn.Config{
		RPDisplayName:         rpDisplayName,
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

	config, err := webauthn.New(wconfig)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInitialize, model.TypeAuthType, nil, err)
	}

	return &webAuthnAuthImpl{auth: a.auth, authType: a.authType, config: config}, nil
}

func (a *webAuthnAuthImpl) requireIdentifierVerificationForSignIn() bool {
	return true
}

func (a *webAuthnAuthImpl) allowMultiple() bool {
	return true
}

// Helpers

func (a *webAuthnAuthImpl) beginRegistration(user webauthn.User, appOrg model.ApplicationOrganization) (string, error) {
	if a.config.Config.RPDisplayName == rpDisplayNameKey {
		a.config.Config.RPDisplayName = appOrg.Application.Name
	}
	options, session, err := a.config.BeginRegistration(user)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionRegister, model.TypeAccount, nil, err)
	}

	sessionData, err := json.Marshal(session)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionMarshal, "session", nil, err)
	}

	state := map[string]interface{}{stateKeyChallenge: session.Challenge, stateKeySession: string(sessionData)}
	accountID := string(user.WebAuthnID())
	loginState := model.LoginState{ID: uuid.NewString(), AppID: appOrg.Application.ID, OrgID: appOrg.Organization.ID, AccountID: &accountID, State: state, DateCreated: time.Now().UTC()}
	err = a.auth.storage.InsertLoginState(loginState)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionCreate, model.TypeLoginState, nil, err)
	}

	optionData, err := json.Marshal(options)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionMarshal, "creation options", nil, err)
	}

	return string(optionData), nil
}

func (a *webAuthnAuthImpl) completeRegistration(response *protocol.ParsedCredentialCreationData, user webauthn.User, aats []model.AccountAuthType, appOrg model.ApplicationOrganization) (string, error) {
	if user == nil {
		return "", errors.ErrorData(logutils.StatusMissing, model.TypeAccount, nil)
	}

	accountIDVal := string(user.WebAuthnID())
	accountID := &accountIDVal

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

	if a.config.Config.RPDisplayName == rpDisplayNameKey {
		a.config.Config.RPDisplayName = appOrg.Application.Name
	}
	credential, err := a.config.CreateCredential(user, *session, response)
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

	var accountAuthType *model.AccountAuthType
	for i, aat := range aats {
		if aat.Credential == nil {
			accountAuthType = &aats[i]
			break
		}
	}
	if accountAuthType == nil {
		return "", errors.ErrorData(logutils.StatusMissing, "account auth type without credential", &logutils.FieldArgs{"auth_type_code": a.authType, "account_id": accountIDVal})
	}

	credID := uuid.NewString()
	transaction := func(context storage.TransactionContext) error {
		//1. insert new credential
		storeCred := &model.Credential{ID: credID, Value: credData, AccountsAuthTypes: []model.AccountAuthType{*accountAuthType},
			AuthType: model.AuthType{Code: a.authType}, DateCreated: time.Now().UTC()}
		err = a.auth.storage.InsertCredential(context, storeCred)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
		}

		//2. update the credential of the existing account auth type
		accountAuthType.Credential = &model.Credential{ID: credID}
		err = a.auth.storage.UpdateAccountAuthType(context, *accountAuthType)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountAuthType, &logutils.FieldArgs{"id": accountAuthType.ID, "account_id": accountIDVal}, err)
		}

		//3. remove the login state
		err = a.auth.storage.DeleteLoginState(context, loginState.ID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionDelete, model.TypeLoginState, nil, err)
		}

		return nil
	}

	err = a.auth.storage.PerformTransaction(transaction)
	if err != nil {
		return "", err
	}

	return credID, nil
}

func (a *webAuthnAuthImpl) beginLogin(user webauthn.User, appOrg model.ApplicationOrganization) (string, error) {
	var options *protocol.CredentialAssertion
	var session *webauthn.SessionData
	var err error
	var accountID *string
	if a.config.Config.RPDisplayName == rpDisplayNameKey {
		a.config.Config.RPDisplayName = appOrg.Application.Name
	}
	if user != nil {
		options, session, err = a.config.BeginLogin(user)
		if err != nil {
			return "", errors.WrapErrorAction(logutils.ActionStart, "login", nil, err)
		}
		accountIDVal := string(user.WebAuthnID())
		accountID = &accountIDVal
	} else {
		// if no user, we can start a discoverable login
		options, session, err = a.config.BeginDiscoverableLogin()
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

func (a *webAuthnAuthImpl) completeLogin(response *protocol.ParsedCredentialAssertionData, user webauthn.User, aats []model.AccountAuthType, appOrg model.ApplicationOrganization) (string, error) {
	if a.config.Config.RPDisplayName == rpDisplayNameKey {
		a.config.Config.RPDisplayName = appOrg.Application.Name
	}

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
		updatedCred, err = a.config.ValidateLogin(user, *session, response)
		if err != nil {
			return "", errors.WrapErrorAction(logutils.ActionValidate, "login", nil, err)
		}

		// find matching credential in provided list
		for _, aat := range aats {
			if aat.Credential != nil {
				webAuthnCred, err := a.parseWebAuthnCredential(aat.Credential.Value)
				if err != nil {
					return "", errors.WrapErrorAction(logutils.ActionParse, "webauthn credential", nil, err)
				}

				if webAuthnCred != nil && bytes.Equal(updatedCred.ID, webAuthnCred.ID) {
					credential = aat.Credential
					break
				}
			}
		}
	} else {
		// if no user, we can validate a discoverable login
		userDiscoverer := func(rawID, userHandle []byte) (webauthn.User, error) {
			legacyUserHandle := false

			// find account by userHandle (should match an account ID)
			account, err := a.auth.storage.FindAccountByID(nil, &appOrg.Organization.ID, &appOrg.Application.ID, string(userHandle))
			if err != nil {
				return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, &logutils.FieldArgs{"userHandle": string(userHandle)}, err)
			}
			if account == nil {
				// backwards compatibility: user handles (user IDs) used to be credential IDs
				// check if the user handle matches any of the user's webauthn credential IDs
				account, err = a.auth.storage.FindAccountByCredentialID(nil, string(userHandle), &appOrg.ID)
				if err != nil {
					return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, &logutils.FieldArgs{"userHandle": string(userHandle), "legacy": true}, err)
				}

				if account == nil {
					return nil, errors.ErrorData(logutils.StatusMissing, model.TypeAccount, &logutils.FieldArgs{"userHandle": string(userHandle)})
				}
				legacyUserHandle = true
			}

			// find matching credential by rawId (should match a credential ID)
			aats, err := a.auth.findAccountAuthTypesAndCredentials(account, model.SupportedAuthType{AuthType: model.AuthType{Code: a.authType}})
			for _, aat := range aats {
				if aat.Credential != nil {
					webAuthnCred, err := a.parseWebAuthnCredential(aat.Credential.Value)
					if err != nil {
						return nil, errors.WrapErrorAction(logutils.ActionParse, "webauthn credential", nil, err)
					}

					if webAuthnCred != nil && bytes.Equal(rawID, webAuthnCred.ID) {
						credential = aat.Credential
						userID := account.ID
						if legacyUserHandle {
							userID = credential.ID
						}
						return webAuthnUser{ID: userID, Credentials: []webauthn.Credential{*webAuthnCred}}, nil
					}
				}
			}

			return nil, errors.ErrorData(logutils.StatusMissing, "user", &logutils.FieldArgs{"userHandle": string(userHandle), "rawID": string(rawID)})
		}

		updatedCred, err = a.config.ValidateDiscoverableLogin(userDiscoverer, *session, response)
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
		transaction := func(context storage.TransactionContext) error {
			//1. update credential
			err = a.auth.storage.UpdateCredentialValue(context, credID, credential.Value)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
			}

			//2. remove the login state
			err = a.auth.storage.DeleteLoginState(context, loginState.ID)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionDelete, model.TypeLoginState, nil, err)
			}

			return nil
		}

		err = a.auth.storage.PerformTransaction(transaction)
		if err != nil {
			return "", err
		}
	}

	return credID, nil
}

func (a *webAuthnAuthImpl) buildUser(accountID *string, aats []model.AccountAuthType) (webauthn.User, error) {
	var user webauthn.User

	userCredentials := make([]webauthn.Credential, 0)
	for _, aat := range aats {
		if aat.Credential != nil {
			webAuthnCred, err := a.parseWebAuthnCredential(aat.Credential.Value)
			if err != nil {
				return nil, errors.WrapErrorAction(logutils.ActionParse, "webauthn credential", nil, err)
			}

			// have at least one valid webauthn credential, so initiate login
			if webAuthnCred != nil {
				userCredentials = append(userCredentials, *webAuthnCred)
			}
		}
	}

	if accountID != nil { // otherwise identifier-less login
		user = webAuthnUser{ID: *accountID, Credentials: userCredentials}
	}

	return user, nil
}

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
	creds, err := utils.JSONConvert[webauthnCreds, map[string]interface{}](credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionParse, typeWebAuthnCreds, nil, err)
	}

	err = validator.New().Struct(creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, typeWebAuthnCreds, nil, err)
	}
	return creds, nil
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
