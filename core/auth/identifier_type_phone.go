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
	"net/url"
	"regexp"
	"time"

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
	"gopkg.in/go-playground/validator.v9"
)

const (
	//IdentifierTypePhone phone identifier type
	IdentifierTypePhone string = "phone"

	typePhoneCreds  logutils.MessageDataType = "phone creds"
	typePhoneParams logutils.MessageDataType = "phone params"
	typePhoneNumber logutils.MessageDataType = "E.164 phone number"
)

type phoneCreds struct {
	Phone      string  `json:"phone" bson:"phone" validate:"required"`
	Code       *string `json:"code,omitempty"`
	Password   *string `json:"password,omitempty" bson:"password,omitempty"`
	Session    *string `json:"session,omitempty" bson:"session,omitempty"`
	Credential *string `json:"credential,omitempty" bson:"credential,omitempty"`
	Response   *string `json:"response,omitempty"`
}

func (c *phoneCreds) identifier() string {
	return c.Phone
}

func (c *phoneCreds) getAuthType() string {
	if c.Password != nil {
		return AuthTypePassword
	} else if c.Session != nil || c.Credential != nil || c.Response != nil {
		return AuthTypeWebAuthn
	}
	return AuthTypeCode // default
}

func (c *phoneCreds) getCredential(key string) string {
	if key == credentialKeyCode && c.Code != nil {
		return *c.Code
	} else if key == credentialKeyPassword && c.Password != nil {
		return *c.Password
	} else if key == credentialKeyResponse && c.Response != nil {
		return *c.Response
	} else if key == credentialKeySession && c.Session != nil {
		return *c.Session
	} else if key == credentialKeyCredential && c.Credential != nil {
		return *c.Credential
	}
	return ""
}

func (c *phoneCreds) setCredential(value string, key string) {
	if key == credentialKeyCode {
		c.Code = &value
	} else if key == credentialKeyPassword {
		c.Password = &value
	} else if key == credentialKeyResponse {
		c.Response = &value
	} else if key == credentialKeySession {
		c.Session = &value
	} else if key == credentialKeyCredential {
		c.Credential = &value
	}
}

func (c *phoneCreds) getVerificationParams() (string, *time.Time) {
	return "", nil
}

func (c *phoneCreds) setVerificationParams(code string, expiry *time.Time) {}

func (c *phoneCreds) getResetParams() (string, *time.Time) {
	return "", nil
}

func (c *phoneCreds) setResetParams(code string, expiry *time.Time) {}

func (c *phoneCreds) toMap() (map[string]interface{}, error) {
	credBytes, err := json.Marshal(c)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typePhoneCreds, nil, err)
	}
	var credsMap map[string]interface{}
	err = json.Unmarshal(credBytes, &credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, "phone creds map", nil, err)
	}
	return credsMap, nil
}

type phoneParams struct {
	DisplayName *string `json:"display_name"`
}

func (p *phoneParams) parameter(key string) string {
	if key == parameterKeyDisplayName && p.DisplayName != nil {
		return *p.DisplayName
	}
	return ""
}

// Phone implementation of identifierType
type phoneIdentifierImpl struct {
	auth           *Auth
	identifierType string
}

func (a *phoneIdentifierImpl) getType() string {
	return IdentifierTypePhone
}

func (a *phoneIdentifierImpl) getUserIdentifier(creds string) (string, error) {
	var requestCreds phoneCreds
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, typePhoneCreds, nil, err)
	}

	return requestCreds.Phone, nil
}

func (a *phoneIdentifierImpl) parseCreds(creds string) (authCreds, error) {
	var credential phoneCreds
	err := json.Unmarshal([]byte(creds), &credential)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePhoneCreds, nil, err)
	}

	validate := validator.New()
	err = validate.Struct(credential)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, typePhoneCreds, nil, err)
	}

	validPhone := regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
	if !validPhone.MatchString(credential.Phone) {
		return nil, errors.ErrorData(logutils.StatusInvalid, typePhoneNumber, &logutils.FieldArgs{"phone": credential.Phone})
	}

	return &credential, nil
}

func (a *phoneIdentifierImpl) parseParams(params string) (authParams, error) {
	var parameters phoneParams
	err := json.Unmarshal([]byte(params), &parameters)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePhoneParams, nil, err)
	}

	return &parameters, nil
}

func (a *phoneIdentifierImpl) mapToCreds(credsMap map[string]interface{}) (authCreds, error) {
	credBytes, err := json.Marshal(credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, "phone creds map", nil, err)
	}
	var creds phoneCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePhoneCreds, nil, err)
	}
	return &creds, nil
}

func (a *phoneIdentifierImpl) buildCredential(identifier string, credential string, key string) authCreds {
	if key == credentialKeyCode {
		return &phoneCreds{Phone: identifier, Code: &credential}
	} else if key == credentialKeyPassword {
		return &phoneCreds{Phone: identifier, Password: &credential}
	} else if key == credentialKeySession {
		return &phoneCreds{Phone: identifier, Session: &credential}
	} else if key == credentialKeyCredential {
		return &phoneCreds{Phone: identifier, Credential: &credential}
	}
	return nil
}

// authCommunicationChannel interface

func (a *phoneIdentifierImpl) verifyCredential(credential authCreds, verification string) (map[string]interface{}, error) {
	_, err := a.sendCode(credential.identifier(), "", verification, "", "")
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionSend, "verification code", nil, err)
	}

	credsMap, err := credential.toMap()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, "map from phone creds", nil, err)
	}

	return credsMap, nil
}

func (a *phoneIdentifierImpl) sendVerifyCredential(credential authCreds, appName string, credID string) (map[string]interface{}, bool, error) {
	//send verification code
	if _, err := a.sendCode(credential.identifier(), appName, "", typeVerificationCode, credID); err != nil {
		return nil, false, errors.WrapErrorAction(logutils.ActionSend, "verification phone", nil, err)
	}

	//Update verification data in credential value
	credsMap, err := credential.toMap()
	if err != nil {
		return nil, true, errors.WrapErrorAction(logutils.ActionCast, "map from phone creds", nil, err)
	}

	return credsMap, true, nil
}

func (a *phoneIdentifierImpl) restartCredentialVerification(credential authCreds, appName string, credID string) (map[string]interface{}, error) {
	//TODO: do twilio/other phone verifiers have verification timeouts?
	return nil, errors.New(logutils.Unimplemented)
}

func (a *phoneIdentifierImpl) isCredentialVerified(credential *model.Credential) (*bool, *bool, error) {
	verified := credential.Verified
	return &verified, nil, nil
}

func (a *phoneIdentifierImpl) sendCode(identifier string, appName string, code string, codeType string, credID string) (string, error) {
	data := url.Values{}
	data.Add("To", identifier)
	if code != "" {
		// check verification
		data.Add("Code", code)
		return "", a.auth.phoneVerifier.CheckVerification(identifier, data)
	}

	// start verification
	data.Add("Channel", "sms")

	message := ""
	err := a.auth.phoneVerifier.StartVerification(identifier, data)
	if err == nil {
		message = "verification code sent successfully"
	}
	return message, err
}

func (a *phoneIdentifierImpl) requiresCodeGeneration() bool {
	return false
}

// initPhoneIdentifier initializes and registers a new phone identifier instance
func initPhoneIdentifier(auth *Auth) (*phoneIdentifierImpl, error) {
	phone := &phoneIdentifierImpl{auth: auth, identifierType: IdentifierTypePhone}

	err := auth.registerIdentifierType(phone.identifierType, phone)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeIdentifierType, nil, err)
	}

	return phone, nil
}
