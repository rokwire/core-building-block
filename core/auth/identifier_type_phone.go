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
	"github.com/rokwire/logging-library-go/v2/logutils"
	"gopkg.in/go-playground/validator.v9"
)

const (
	//IdentifierTypePhone phone identifier type
	IdentifierTypePhone string = "phone"

	typePhoneIdentifier logutils.MessageDataType = "phone identifier"
	typePhoneNumber     logutils.MessageDataType = "E.164 phone number"
)

type phoneIdentifier struct {
	Phone string `json:"phone" validate:"required"`
}

// Phone implementation of identifierType
type phoneIdentifierImpl struct {
	auth *Auth
	code string

	identifier *string
}

func (a *phoneIdentifierImpl) getCode() string {
	return a.code
}

func (a *phoneIdentifierImpl) getUserIdentifier(creds string) (string, error) {
	if a.identifier != nil {
		return *a.identifier, nil
	}

	var requestCreds phoneIdentifier
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, typePhoneIdentifier, nil, err)
	}

	err = validator.New().Struct(requestCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionValidate, typePhoneIdentifier, nil, err)
	}

	validPhone := regexp.MustCompile(`^\+[1-9]\d{1,14}$`)
	if !validPhone.MatchString(requestCreds.Phone) {
		return "", errors.ErrorData(logutils.StatusInvalid, typePhoneNumber, &logutils.FieldArgs{"phone": requestCreds.Phone})
	}

	a.identifier = &requestCreds.Phone
	return requestCreds.Phone, nil
}

func (a *phoneIdentifierImpl) withIdentifier(identifier string) identifierType {
	return &phoneIdentifierImpl{auth: a.auth, code: a.code, identifier: &identifier}
}

// authCommunicationChannel interface

func (a *phoneIdentifierImpl) verifyIdentifier(accountIdentifier *model.AccountIdentifier, verification string) error {
	_, err := a.sendCode("", verification, "", "")
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSend, "verification code", nil, err)
	}

	return nil
}

func (a *phoneIdentifierImpl) sendVerifyCredential(accountIdentifier *model.AccountIdentifier, appName string) (bool, error) {
	if accountIdentifier == nil {
		return false, errors.ErrorData(logutils.StatusMissing, model.TypeAccountIdentifier, nil)
	}

	//send verification code
	if _, err := a.sendCode(appName, "", typeVerificationCode, accountIdentifier.ID); err != nil {
		return false, errors.WrapErrorAction(logutils.ActionSend, "verification phone", nil, err)
	}

	return true, nil
}

func (a *phoneIdentifierImpl) restartCredentialVerification(accountIdentifier *model.AccountIdentifier, appName string) error {
	//TODO: do twilio/other phone verifiers have verification timeouts?
	return errors.New(logutils.Unimplemented)
}

func (a *phoneIdentifierImpl) sendCode(appName string, code string, codeType string, itemID string) (string, error) {
	if a.identifier == nil {
		return "", errors.ErrorData(logutils.StatusMissing, typeEmailIdentifier, nil)
	}

	data := url.Values{}
	data.Add("To", *a.identifier)
	if code != "" {
		// check verification
		data.Add("Code", code)
		return "", a.auth.phoneVerifier.CheckVerification(*a.identifier, data)
	}

	// start verification
	data.Add("Channel", "sms")

	message := ""
	err := a.auth.phoneVerifier.StartVerification(*a.identifier, data)
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
	phone := &phoneIdentifierImpl{auth: auth, code: IdentifierTypePhone}

	err := auth.registerIdentifierType(phone.code, phone)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeIdentifierType, nil, err)
	}

	return phone, nil
}
