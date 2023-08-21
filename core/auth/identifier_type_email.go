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
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rokwire/core-auth-library-go/v3/authutils"
	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
	"gopkg.in/go-playground/validator.v9"
)

const (
	//IdentifierTypeEmail email identifier type
	IdentifierTypeEmail string = "email"

	typeEmailIdentifier logutils.MessageDataType = "email identifier"
)

type emailIdentifier struct {
	Email string `json:"email" validate:"required"`
}

// Email implementation of identifierType
type emailIdentifierImpl struct {
	auth *Auth
	code string

	identifier string
}

func (a *emailIdentifierImpl) getCode() string {
	return a.code
}

func (a *emailIdentifierImpl) getIdentifier() string {
	return a.identifier
}

func (a *emailIdentifierImpl) withIdentifier(creds string) (identifierType, error) {
	var requestCreds emailIdentifier
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeEmailIdentifier, nil, err)
	}

	err = validator.New().Struct(requestCreds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, typeEmailIdentifier, nil, err)
	}

	return &emailIdentifierImpl{auth: a.auth, code: a.code, identifier: strings.TrimSpace(requestCreds.Email)}, nil
}

func (a *emailIdentifierImpl) buildIdentifier(accountID *string, appName string) (string, *model.AccountIdentifier, error) {
	if a.identifier == "" {
		return "", nil, errors.ErrorData(logutils.StatusMissing, "email identifier", nil)
	}

	accountIDStr := ""
	if accountID != nil {
		accountIDStr = *accountID
	} else {
		accountIDStr = uuid.NewString()
	}

	message := ""
	accountIdentifier := model.AccountIdentifier{ID: uuid.NewString(), Code: a.code, Identifier: a.identifier, Verified: false,
		Account: model.Account{ID: accountIDStr}, DateCreated: time.Now().UTC()}
	sent, err := a.sendVerifyIdentifier(&accountIdentifier, appName)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionSend, "identifier verification", nil, err)
	}
	if sent {
		message = "verification code sent successfully"
	}

	return message, &accountIdentifier, nil
}

// authCommunicationChannel interface

func (a *emailIdentifierImpl) verifyIdentifier(accountIdentifier *model.AccountIdentifier, verification string) error {
	if accountIdentifier == nil {
		return errors.ErrorData(logutils.StatusMissing, model.TypeAccountIdentifier, nil)
	}

	if accountIdentifier.VerificationExpiry == nil || accountIdentifier.VerificationExpiry.Before(time.Now()) {
		return errors.ErrorData("expired", "email verification code", nil)
	}
	if accountIdentifier.VerificationCode == nil {
		return errors.ErrorData(logutils.StatusMissing, "email verification code", nil)
	}
	if subtle.ConstantTimeCompare([]byte(*accountIdentifier.VerificationCode), []byte(verification)) == 0 {
		return errors.ErrorData(logutils.StatusInvalid, "email verification code", nil)
	}

	//Update verification data
	now := time.Now().UTC()
	accountIdentifier.Verified = true
	accountIdentifier.VerificationCode = nil
	accountIdentifier.VerificationExpiry = nil
	accountIdentifier.DateUpdated = &now
	return nil
}

func (a *emailIdentifierImpl) sendVerifyIdentifier(accountIdentifier *model.AccountIdentifier, appName string) (bool, error) {
	if accountIdentifier == nil {
		return false, errors.ErrorData(logutils.StatusMissing, model.TypeAccountIdentifier, nil)
	}

	//verification settings
	verifyWaitTime, verifyExpiryTime, err := a.getVerificationSettings()
	if err != nil {
		return false, errors.WrapErrorAction(logutils.ActionGet, "email verification settings", nil, err)
	}
	if verifyWaitTime == nil || verifyExpiryTime == nil {
		return false, nil
	}

	//Check if previous verification email was sent within the wait time if one was already sent
	if accountIdentifier.VerificationExpiry != nil {
		prevTime := accountIdentifier.VerificationExpiry.Add(time.Duration(-*verifyExpiryTime) * time.Hour)
		if time.Now().Sub(prevTime) < time.Duration(*verifyWaitTime)*time.Second {
			return false, errors.ErrorAction(logutils.ActionSend, "verification email", logutils.StringArgs("resend requested too soon"))
		}
	}

	//verification code
	//TODO: turn length of reset code into a setting
	code, err := utils.GenerateRandomString(64)
	if err != nil {
		return false, errors.WrapErrorAction(logutils.ActionGenerate, "verification code", nil, err)
	}

	//send verification email
	if _, err = a.sendCode(appName, code, typeVerificationCode, accountIdentifier.ID); err != nil {
		return false, errors.WrapErrorAction(logutils.ActionSend, "verification email", nil, err)
	}

	//Update verification data in credential value
	now := time.Now().UTC()
	newExpiry := now.Add(time.Hour * time.Duration(*verifyExpiryTime))
	accountIdentifier.VerificationCode = &code
	accountIdentifier.VerificationExpiry = &newExpiry
	accountIdentifier.DateUpdated = &now
	return true, nil
}

func (a *emailIdentifierImpl) restartIdentifierVerification(accountIdentifier *model.AccountIdentifier, appName string) error {
	if accountIdentifier == nil {
		return errors.ErrorData(logutils.StatusMissing, model.TypeAccountIdentifier, nil)
	}

	//Generate new verification code
	//TODO: turn length of reset code into a setting
	newCode, err := utils.GenerateRandomString(64)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionGenerate, "verification code", nil, err)

	}
	//send new verification code for future
	if _, err = a.sendCode(appName, newCode, typeVerificationCode, accountIdentifier.ID); err != nil {
		return errors.WrapErrorAction(logutils.ActionSend, "verification email", nil, err)
	}
	//update new verification data in credential value
	expiry := time.Now().Add(time.Hour * 24)
	accountIdentifier.VerificationCode = &newCode
	accountIdentifier.VerificationExpiry = &expiry
	return nil
}

func (a *emailIdentifierImpl) sendCode(appName string, code string, codeType string, itemID string) (string, error) {
	if a.identifier == "" {
		return "", errors.ErrorData(logutils.StatusMissing, typeEmailIdentifier, nil)
	}

	params := url.Values{}
	params.Add("id", itemID)
	params.Add("code", code)
	switch codeType {
	case typePasswordResetCode:
		passwordResetLink := a.auth.host + fmt.Sprintf("/ui/credential/reset?%s", params.Encode())
		subject := "Reset your password"
		if appName != "" {
			subject += " for " + appName
		}
		body := "Please click the link below to reset your password:<br><a href=" + passwordResetLink + ">" + passwordResetLink + "</a><br><br>If you did not request a password reset, please ignore this message."
		return "", a.auth.emailer.Send(a.identifier, subject, body, nil)
	case typeVerificationCode:
		verificationLink := a.auth.host + fmt.Sprintf("/ui/identifier/verify?%s", params.Encode())
		subject := "Verify your email address"
		if appName != "" {
			subject += " for " + appName
		}
		body := "Please click the link below to verify your email address:<br><a href=" + verificationLink + ">" + verificationLink + "</a><br><br>If you did not request this verification link, please ignore this message."
		return "", a.auth.emailer.Send(a.identifier, subject, body, nil)
	case typeAuthenticationCode:
		subject := "Your authentication code"
		body := "Please use the code " + code + " to login"
		if appName != "" {
			subject += " for " + appName
			body += " to " + appName
		}
		body += ". If you did not request this authentication code, please ignore this message."
		return "", a.auth.emailer.Send(a.identifier, subject, body, nil)
	default:
		return "", errors.ErrorData(logutils.StatusInvalid, "code type", logutils.StringArgs(codeType))
	}
}

func (a *emailIdentifierImpl) requiresCodeGeneration() bool {
	return true
}

func (a *emailIdentifierImpl) allowMultiple() bool {
	return true
}

// Helpers

func (a *emailIdentifierImpl) getVerificationSettings() (*int, *int, error) {
	// Time in seconds to wait before sending another auth code (default is 30)
	verifyWaitTime := 30
	// Time in hours before auth code expires (default is 24)
	verifyExpiry := 24

	config, err := a.auth.storage.FindConfig(model.ConfigTypeAuth, authutils.AllApps, authutils.AllOrgs)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeConfig, &logutils.FieldArgs{"type": model.ConfigTypeAuth, "app_id": authutils.AllApps, "org_id": authutils.AllOrgs}, err)
	}
	if config != nil {
		authConfigData, err := model.GetConfigData[model.AuthConfigData](*config)
		if err != nil {
			return nil, nil, errors.WrapErrorAction(logutils.ActionParse, model.TypeAuthConfigData, nil, err)
		}

		// Should email addresses be verified (default is true)
		if authConfigData.EmailShouldVerify != nil && !*authConfigData.EmailShouldVerify {
			return nil, nil, nil
		}

		if authConfigData.EmailVerifyWaitTime != nil {
			verifyWaitTime = *authConfigData.EmailVerifyWaitTime
		}

		if authConfigData.EmailVerifyExpiry != nil {
			verifyExpiry = *authConfigData.EmailVerifyExpiry
		}
	}

	return &verifyWaitTime, &verifyExpiry, nil
}

// initEmailIdentifier initializes and registers a new email identifier instance
func initEmailIdentifier(auth *Auth) (*emailIdentifierImpl, error) {
	email := &emailIdentifierImpl{auth: auth, code: IdentifierTypeEmail}

	err := auth.registerIdentifierType(email.code, email)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeIdentifierType, nil, err)
	}

	return email, nil
}
