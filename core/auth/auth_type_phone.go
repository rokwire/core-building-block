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

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logs"
	"github.com/rokwire/logging-library-go/v2/logutils"
	"gopkg.in/go-playground/validator.v9"
)

const (
	//AuthTypePhone phone auth type
	AuthTypePhone string = "phone"

	typePhoneCreds  logutils.MessageDataType = "phone creds"
	typePhoneNumber logutils.MessageDataType = "E.164 phone number"
)

// Phone implementation of authType
type phoneAuthImpl struct {
	auth     *Auth
	authType string
	verifier PhoneVerifier
}

type twilioPhoneCreds struct {
	Phone string `json:"phone" validate:"required"`
	Code  string `json:"code"`
	// TODO: Password?
}

func (a *phoneAuthImpl) checkRequestCreds(creds string) (*twilioPhoneCreds, error) {
	var requestCreds twilioPhoneCreds
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePhoneCreds, nil, err)
	}

	validate := validator.New()
	err = validate.Struct(requestCreds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, typePhoneCreds, nil, err)
	}

	phone := requestCreds.Phone
	validPhone := regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
	if !validPhone.MatchString(phone) {
		return nil, errors.ErrorData(logutils.StatusInvalid, typePhoneNumber, &logutils.FieldArgs{"phone": phone})
	}

	return &requestCreds, nil
}

func (a *phoneAuthImpl) signUp(authType model.AuthType, appName string, creds string, params string, newCredentialID string, l *logs.Log) (string, map[string]interface{}, error) {
	requestCreds, err := a.checkRequestCreds(creds)
	if err != nil {
		return "", nil, err
	}

	message, err := a.handlePhoneVerify(requestCreds.Phone, *requestCreds, l)
	if err != nil {
		return "", nil, err
	}

	return message, nil, nil
}

func (a *phoneAuthImpl) signUpAdmin(authType model.AuthType, appName string, identifier string, password string, newCredentialID string) (map[string]interface{}, map[string]interface{}, error) {
	return nil, nil, nil
}

func (a *phoneAuthImpl) isCredentialVerified(credential *model.Credential, l *logs.Log) (*bool, *bool, error) {
	return nil, nil, nil
}

func (a *phoneAuthImpl) checkCredentials(accountAuthType model.AccountAuthType, creds string, l *logs.Log) (string, error) {
	requestCreds, err := a.checkRequestCreds(creds)
	if err != nil {
		return "", err
	}

	// existing user
	message, err := a.handlePhoneVerify(requestCreds.Phone, *requestCreds, l)
	if err != nil {
		return "", err
	}

	return message, nil
}

func (a *phoneAuthImpl) handlePhoneVerify(phone string, verificationCreds twilioPhoneCreds, l *logs.Log) (string, error) {
	data := url.Values{}
	data.Add("To", phone)
	if verificationCreds.Code != "" {
		// check verification
		data.Add("Code", verificationCreds.Code)
		return "", a.verifier.CheckVerification(phone, data)
	}

	// start verification
	data.Add("Channel", "sms")

	message := ""
	err := a.verifier.StartVerification(phone, data)
	if err == nil {
		message = "verification code sent successfully"
	}
	return message, err
}

func (a *phoneAuthImpl) getUserIdentifier(creds string) (string, error) {
	var requestCreds twilioPhoneCreds
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, typePhoneCreds, nil, err)
	}

	return requestCreds.Phone, nil
}

func (a *phoneAuthImpl) verifyCredential(credential *model.Credential, verification string, l *logs.Log) (map[string]interface{}, error) {
	return nil, errors.New(logutils.Unimplemented)
}

func (a *phoneAuthImpl) sendVerifyCredential(credential *model.Credential, appName string, l *logs.Log) error {
	return nil
}

func (a *phoneAuthImpl) restartCredentialVerification(credential *model.Credential, appName string, l *logs.Log) error {
	return nil
}

func (a *phoneAuthImpl) resetCredential(credential *model.Credential, resetCode *string, params string, l *logs.Log) (map[string]interface{}, error) {
	return nil, nil
}

func (a *phoneAuthImpl) forgotCredential(credential *model.Credential, identifier string, appName string, l *logs.Log) (map[string]interface{}, error) {
	return nil, nil
}

// initPhoneAuth initializes and registers a new phone auth instance
func initPhoneAuth(auth *Auth, verifier PhoneVerifier) (*phoneAuthImpl, error) {
	phone := &phoneAuthImpl{auth: auth, authType: verifier.Identifier(), verifier: verifier}

	err := auth.registerAuthType(phone.authType, phone)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAuthType, nil, err)
	}

	return phone, nil
}
