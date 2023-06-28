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
	"encoding/json"
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

type twilioPhoneCreds struct {
	Phone string  `json:"phone" validate:"required"`
	Code  *string `json:"code"`
}

func (c *twilioPhoneCreds) identifier() string {
	return c.Phone
}

func (c *twilioPhoneCreds) getCredential() (string, string) {
	if c.Code != nil {
		return AuthTypeCode, *c.Code
	}
	return "", ""
}

func (c *twilioPhoneCreds) setCredential(value string, credType string) {
	if credType == AuthTypeCode {
		c.Code = &value
	}
}

func (c *twilioPhoneCreds) getVerificationParams() (string, *time.Time) {
	return "", nil
}

func (c *twilioPhoneCreds) setVerificationParams(code string, expiry *time.Time) {}

func (c *twilioPhoneCreds) getResetParams() (string, *time.Time) {
	return "", nil
}

func (c *twilioPhoneCreds) setResetParams(code string, expiry *time.Time) {}

func (c *twilioPhoneCreds) toMap() (map[string]interface{}, error) {
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

type twilioPhoneParams struct {
	ConfirmPassword *string `json:"confirm_password"`
}

func (p *twilioPhoneParams) parameter() (string, string) {
	if p.ConfirmPassword != nil {
		return AuthTypePassword, *p.ConfirmPassword
	}
	return "", ""
}

// Phone implementation of identifierType
type twilioPhoneIdentifierImpl struct {
	identifierType string
	verifier       PhoneVerifier
}

func (a *twilioPhoneIdentifierImpl) getUserIdentifier(creds string) (string, error) {
	var requestCreds twilioPhoneCreds
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, typePhoneCreds, nil, err)
	}

	return requestCreds.Phone, nil
}

func (a *twilioPhoneIdentifierImpl) parseCreds(creds string) (authCreds, error) {
	var credential twilioPhoneCreds
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

func (a *twilioPhoneIdentifierImpl) parseParams(params string) (authParams, error) {
	return nil, nil
}

func (a *twilioPhoneIdentifierImpl) mapToCreds(credsMap map[string]interface{}) (authCreds, error) {
	credBytes, err := json.Marshal(credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, "phone creds map", nil, err)
	}
	var creds twilioPhoneCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePhoneCreds, nil, err)
	}
	return &creds, nil
}

func (a *twilioPhoneIdentifierImpl) buildCredential(identifier string, credential string, credType string) authCreds {
	if credType == AuthTypePassword {
		return &twilioPhoneCreds{Phone: identifier, Code: &credential}
	}
	return nil
}

func (a *twilioPhoneIdentifierImpl) verificationType() string {
	//TODO: how to get verification type and params?
	return ""
}

// initPhoneIdentifier initializes and registers a new phone identifier instance
func initPhoneIdentifier(auth *Auth, verifier PhoneVerifier) (*twilioPhoneIdentifierImpl, error) {
	phone := &twilioPhoneIdentifierImpl{identifierType: verifier.Identifier(), verifier: verifier}

	err := auth.registerIdentifierType(phone.identifierType, phone)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeIdentifierType, nil, err)
	}

	return phone, nil
}
