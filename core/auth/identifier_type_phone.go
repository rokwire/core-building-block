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
	"core-building-block/utils"
	"encoding/json"
	"net/url"
	"time"

	"github.com/google/uuid"
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

	identifier string
}

func (a *phoneIdentifierImpl) getCode() string {
	return a.code
}

func (a *phoneIdentifierImpl) getIdentifier() string {
	return a.identifier
}

func (a *phoneIdentifierImpl) withIdentifier(creds string) (identifierType, error) {
	var requestCreds phoneIdentifier
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePhoneIdentifier, nil, err)
	}

	err = validator.New().Struct(requestCreds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, typePhoneIdentifier, nil, err)
	}

	if !utils.IsValidPhone(requestCreds.Phone) {
		return nil, errors.ErrorData(logutils.StatusInvalid, typePhoneNumber, &logutils.FieldArgs{"phone": requestCreds.Phone})
	}

	return &phoneIdentifierImpl{auth: a.auth, code: a.code, identifier: requestCreds.Phone}, nil
}

func (a *phoneIdentifierImpl) buildIdentifier(accountID *string, appName string) (string, *model.AccountIdentifier, error) {
	if a.identifier == "" {
		return "", nil, errors.ErrorData(logutils.StatusMissing, "phone identifier", nil)
	}

	accountIDStr := ""
	if accountID != nil {
		accountIDStr = *accountID
	} else {
		accountIDStr = uuid.NewString()
	}

	message := ""
	accountIdentifier := model.AccountIdentifier{ID: uuid.NewString(), Code: a.code, Identifier: a.identifier, Verified: false,
		Sensitive: true, Account: model.Account{ID: accountIDStr}, DateCreated: time.Now().UTC()}
	sent, err := a.sendVerifyIdentifier(&accountIdentifier, appName)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionSend, "phone verification", nil, err)
	}
	if sent {
		message = "verification code sent successfully"
	}

	return message, &accountIdentifier, nil
}

func (a *phoneIdentifierImpl) maskIdentifier() (string, error) {
	return utils.GetLogValue(a.identifier, 4), nil // mask all but the last 4 phone digits
}

func (a *phoneIdentifierImpl) requireVerificationForSignIn() bool {
	return false
}

func (a *phoneIdentifierImpl) checkVerified(accountIdentifier *model.AccountIdentifier, appName string) error {
	verified := accountIdentifier.Verified
	expired := accountIdentifier.VerificationExpiry == nil || accountIdentifier.VerificationExpiry.Before(time.Now())

	if !verified {
		//it is unverified
		if !expired {
			//not expired, just notify the client that it is "unverified"
			return errors.ErrorData("unverified", model.TypeAccountIdentifier, nil).SetStatus(utils.ErrorStatusUnverified)
		}

		//restart identifier verification
		err := a.restartIdentifierVerification(accountIdentifier, appName)
		if err != nil {
			return errors.WrapErrorAction("restarting", "identifier verification", nil, err)
		}

		//notify the client that it is unverified and verification is restarted
		return errors.ErrorData("expired", "identifier verification", nil).SetStatus(utils.ErrorStatusVerificationExpired)
	}

	return nil
}

func (a *phoneIdentifierImpl) allowMultiple() bool {
	return true
}

// authCommunicationChannel interface

func (a *phoneIdentifierImpl) verifyIdentifier(accountIdentifier *model.AccountIdentifier, verification string) error {
	_, err := a.sendCode("", verification, "", "")
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionVerify, "verification code", nil, err)
	}

	//TODO: do twilio/other phone verifiers have verification timeouts?
	accountIdentifier.Verified = true
	return nil
}

func (a *phoneIdentifierImpl) sendVerifyIdentifier(accountIdentifier *model.AccountIdentifier, appName string) (bool, error) {
	if accountIdentifier == nil {
		return false, errors.ErrorData(logutils.StatusMissing, model.TypeAccountIdentifier, nil)
	}

	//send verification code
	if _, err := a.sendCode(appName, "", typeVerificationCode, accountIdentifier.ID); err != nil {
		return false, errors.WrapErrorAction(logutils.ActionSend, "verification phone", nil, err)
	}

	//TODO: do twilio/other phone verifiers have verification timeouts?
	return true, nil
}

func (a *phoneIdentifierImpl) restartIdentifierVerification(accountIdentifier *model.AccountIdentifier, appName string) error {
	if accountIdentifier == nil {
		return errors.ErrorData(logutils.StatusMissing, model.TypeAccountIdentifier, nil)
	}

	//send new verification code for future
	if _, err := a.sendCode(appName, "", typeVerificationCode, accountIdentifier.ID); err != nil {
		return errors.WrapErrorAction(logutils.ActionSend, "verification text", nil, err)
	}

	return nil
}

func (a *phoneIdentifierImpl) sendCode(appName string, code string, codeType string, itemID string) (string, error) {
	if a.identifier == "" {
		return "", errors.ErrorData(logutils.StatusMissing, typeEmailIdentifier, nil)
	}

	data := url.Values{}
	data.Add("To", a.identifier)
	if code != "" {
		// check verification
		data.Add("Code", code)
		return "", a.auth.phoneVerifier.CheckVerification(a.identifier, data)
	}

	// start verification
	data.Add("Channel", "sms")

	message := ""
	err := a.auth.phoneVerifier.StartVerification(a.identifier, data)
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
