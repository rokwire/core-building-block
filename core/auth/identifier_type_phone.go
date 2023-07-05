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

	servicesPathPart         string                   = "https://verify.twilio.com/v2/Services"
	verificationsPathPart    string                   = "Verifications"
	verificationCheckPart    string                   = "VerificationCheck"
	typeVerifyServiceID      logutils.MessageDataType = "phone verification service id"
	typeVerifyServiceToken   logutils.MessageDataType = "phone verification service token"
	typeVerificationResponse logutils.MessageDataType = "phone verification response"
	typeVerificationStatus   logutils.MessageDataType = "phone verification staus"
	typeVerificationSID      logutils.MessageDataType = "phone verification sid"
	typePhoneCreds           logutils.MessageDataType = "phone creds"
	typePhoneNumber          logutils.MessageDataType = "E.164 phone number"
)

type phoneCreds struct {
	Phone    string  `json:"phone" bson:"phone" validate:"required"`
	Code     *string `json:"code"`
	Password *string `json:"password" bson:"password,omitempty"`
	Response *string `json:"response"`
}

func (c *phoneCreds) identifier() string {
	return c.Phone
}

func (c *phoneCreds) getCredential() (string, string) {
	if c.Code != nil {
		return AuthTypeCode, *c.Code
	} else if c.Password != nil {
		return AuthTypePassword, *c.Password
	} else if c.Response != nil {
		return AuthTypeWebAuthn, *c.Response
	}
	return "", ""
}

func (c *phoneCreds) setCredential(value string, credType string) {
	if credType == AuthTypeCode {
		c.Code = &value
	} else if credType == AuthTypePassword {
		c.Password = &value
	} else if credType == AuthTypeWebAuthn {
		c.Response = &value
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

// Phone implementation of identifierType
type phoneIdentifierImpl struct {
	auth           *Auth
	identifierType string
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

	phone := credential.Phone
	validPhone := regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
	if !validPhone.MatchString(phone) {
		return nil, errors.ErrorData(logutils.StatusInvalid, typePhoneNumber, &logutils.FieldArgs{"phone": phone})
	}

	return &credential, nil
}

func (a *phoneIdentifierImpl) parseParams(params string) (authParams, error) {
	return nil, nil
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

func (a *phoneIdentifierImpl) buildCredential(identifier string, credential string, credType string) authCreds {
	if credType == AuthTypePassword {
		return &phoneCreds{Phone: identifier, Code: &credential}
	}
	return nil
}

func (a *phoneIdentifierImpl) verifyCredential(credential authCreds, verification string) (map[string]interface{}, error) {
	return nil, errors.New(logutils.Unimplemented)
}

func (a *phoneIdentifierImpl) sendVerifyCredential(credential authCreds, appName string, credID string) (map[string]interface{}, bool, error) {
	return nil, false, errors.New(logutils.Unimplemented)
}

func (a *phoneIdentifierImpl) restartCredentialVerification(credential authCreds, appName string, credID string) (map[string]interface{}, error) {
	return nil, errors.New(logutils.Unimplemented)
}

func (a *phoneIdentifierImpl) isCredentialVerified(credential *model.Credential) (*bool, *bool, error) {
	return nil, nil, errors.New(logutils.Unimplemented)
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

// initPhoneIdentifier initializes and registers a new phone identifier instance
func initPhoneIdentifier(auth *Auth) (*phoneIdentifierImpl, error) {
	phone := &phoneIdentifierImpl{auth: auth, identifierType: IdentifierTypePhone}

	err := auth.registerIdentifierType(phone.identifierType, phone)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeIdentifierType, nil, err)
	}

	return phone, nil
}
