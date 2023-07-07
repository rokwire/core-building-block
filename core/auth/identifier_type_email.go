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
	"time"

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

const (
	//IdentifierTypeEmail email identifier type
	IdentifierTypeEmail string = "email"

	typeEmailCreds  logutils.MessageDataType = "email creds"
	typeEmailParams logutils.MessageDataType = "email params"
)

// enailCreds represents the creds struct for email identifier
type emailCreds struct {
	Email              string     `json:"email" bson:"email" validate:"required"`
	Password           *string    `json:"password" bson:"password,omitempty"`
	Session            *string    `json:"session" bson:"session,omitempty"`
	Credential         *string    `json:"credential" bson:"credential,omitempty"`
	Response           *string    `json:"response"`
	Code               *string    `json:"code" bson:"code,omitempty"`
	VerificationCode   string     `json:"verification_code" bson:"verification_code"`
	VerificationExpiry *time.Time `json:"verification_expiry" bson:"verification_expiry"`
	ResetCode          string     `json:"reset_code" bson:"reset_code"`
	ResetExpiry        *time.Time `json:"reset_expiry" bson:"reset_expiry"`
}

func (c *emailCreds) identifier() string {
	return c.Email
}

func (c *emailCreds) getAuthType() string {
	if c.Password != nil {
		return AuthTypePassword
	} else if c.Code != nil {
		return AuthTypeCode
	} else if c.Session != nil || c.Credential != nil || c.Response != nil {
		return AuthTypeWebAuthn
	}
	return ""
}

func (c *emailCreds) getCredential(key string) string {
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

func (c *emailCreds) setCredential(value string, key string) {
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

func (c *emailCreds) getVerificationParams() (string, *time.Time) {
	return c.VerificationCode, c.VerificationExpiry
}

func (c *emailCreds) setVerificationParams(code string, expiry *time.Time) {
	c.VerificationCode = code
	if expiry != nil {
		c.VerificationExpiry = expiry
	}
}

func (c *emailCreds) getResetParams() (string, *time.Time) {
	return c.ResetCode, c.ResetExpiry
}

func (c *emailCreds) setResetParams(code string, expiry *time.Time) {
	c.ResetCode = code
	c.ResetExpiry = expiry
}

func (c *emailCreds) toMap() (map[string]interface{}, error) {
	credBytes, err := json.Marshal(c)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typeEmailCreds, nil, err)
	}
	var credsMap map[string]interface{}
	err = json.Unmarshal(credBytes, &credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, "email creds map", nil, err)
	}
	return credsMap, nil
}

type emailParams struct {
	ConfirmPassword *string `json:"confirm_password"`
	DisplayName     *string `json:"display_name"`
}

func (p *emailParams) parameter(key string) string {
	if key == parameterKeyPassword && p.ConfirmPassword != nil {
		return *p.ConfirmPassword
	} else if key == parameterKeyDisplayName && p.DisplayName != nil {
		return *p.DisplayName
	}
	return ""
}

// Email implementation of identifierType
type emailIdentifierImpl struct {
	auth           *Auth
	identifierType string
}

func (a *emailIdentifierImpl) getUserIdentifier(creds string) (string, error) {
	var requestCreds emailCreds
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, typeEmailCreds, nil, err)
	}

	return requestCreds.Email, nil
}

func (a *emailIdentifierImpl) parseCreds(creds string) (authCreds, error) {
	var credential emailCreds
	err := json.Unmarshal([]byte(creds), &credential)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeEmailCreds, nil, err)
	}

	if len(credential.Email) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, typeEmailCreds, logutils.StringArgs("email"))
	}

	return &credential, nil
}

func (a *emailIdentifierImpl) parseParams(params string) (authParams, error) {
	var parameters emailParams
	err := json.Unmarshal([]byte(params), &parameters)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeEmailParams, nil, err)
	}

	return &parameters, nil
}

func (a *emailIdentifierImpl) mapToCreds(credsMap map[string]interface{}) (authCreds, error) {
	credBytes, err := json.Marshal(credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, "email creds map", nil, err)
	}
	var creds emailCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeEmailCreds, nil, err)
	}
	return &creds, nil
}

func (a *emailIdentifierImpl) buildCredential(identifier string, credential string, key string) authCreds {
	if key == credentialKeyCode {
		return &emailCreds{Email: identifier, Code: &credential}
	} else if key == credentialKeyPassword {
		return &emailCreds{Email: identifier, Password: &credential}
	} else if key == credentialKeySession {
		return &emailCreds{Email: identifier, Session: &credential}
	} else if key == credentialKeyCredential {
		return &emailCreds{Email: identifier, Credential: &credential}
	}
	return nil
}

func (a *emailIdentifierImpl) verifyCredential(credential authCreds, verification string) (map[string]interface{}, error) {
	verificationCode, verificationExpiry := credential.getVerificationParams()
	if verificationExpiry == nil || verificationExpiry.Before(time.Now()) {
		return nil, errors.ErrorData("expired", "email verification code", nil)
	}
	if subtle.ConstantTimeCompare([]byte(verificationCode), []byte(verification)) == 0 {
		return nil, errors.ErrorData(logutils.StatusInvalid, "email verification code", nil)
	}

	//Update verification data
	credential.setVerificationParams("", nil)
	credsMap, err := credential.toMap()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, "map from creds", nil, err)
	}

	return credsMap, nil
}

func (a *emailIdentifierImpl) sendVerifyCredential(credential authCreds, appName string, credID string) (map[string]interface{}, bool, error) {
	//verification settings
	verifyWaitTime, verifyExpiryTime, err := a.getVerificationSettings()
	if err != nil {
		return nil, false, errors.WrapErrorAction(logutils.ActionGet, "email verification settings", nil, err)
	}
	if verifyWaitTime == nil || verifyExpiryTime == nil {
		credsMap, err := credential.toMap()
		if err != nil {
			return nil, false, errors.WrapErrorAction(logutils.ActionCast, "map from email creds", nil, err)
		}
		return credsMap, false, nil
	}

	//Check if previous verification email was sent within the wait time if one was already sent
	_, verificationExpiry := credential.getVerificationParams()
	if verificationExpiry != nil {
		prevTime := verificationExpiry.Add(time.Duration(-*verifyExpiryTime) * time.Hour)
		if time.Now().Sub(prevTime) < time.Duration(*verifyWaitTime)*time.Second {
			return nil, false, errors.ErrorAction(logutils.ActionSend, "verification email", logutils.StringArgs("resend requested too soon"))
		}
	}

	//verification code
	//TODO: turn length of reset code into a setting
	code, err := utils.GenerateRandomString(64)
	if err != nil {
		return nil, false, errors.WrapErrorAction(logutils.ActionGenerate, "verification code", nil, err)
	}

	//send verification email
	if _, err = a.sendCode(credential.identifier(), appName, code, typeVerificationCode, credID); err != nil {
		return nil, false, errors.WrapErrorAction(logutils.ActionSend, "verification email", nil, err)
	}

	//Update verification data in credential value
	newExpiry := time.Now().Add(time.Hour * time.Duration(*verifyExpiryTime))
	credential.setVerificationParams(code, &newExpiry)
	credsMap, err := credential.toMap()
	if err != nil {
		return nil, true, errors.WrapErrorAction(logutils.ActionCast, "map from email creds", nil, err)
	}

	return credsMap, true, nil
}

func (a *emailIdentifierImpl) restartCredentialVerification(credential authCreds, appName string, credID string) (map[string]interface{}, error) {
	//Generate new verification code
	//TODO: turn length of reset code into a setting
	newCode, err := utils.GenerateRandomString(64)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGenerate, "verification code", nil, err)

	}
	//send new verification code for future
	if _, err = a.sendCode(credential.identifier(), appName, newCode, typeVerificationCode, credID); err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionSend, "verification email", nil, err)
	}
	//update new verification data in credential value
	expiry := time.Now().Add(time.Hour * 24)
	credential.setVerificationParams(newCode, &expiry)
	credValueMap, err := credential.toMap()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, "map from creds", nil, err)
	}

	return credValueMap, nil
}

func (a *emailIdentifierImpl) isCredentialVerified(credential *model.Credential) (*bool, *bool, error) {
	if credential.Verified {
		verified := true
		return &verified, nil, nil
	}

	//verification settings
	verifyWaitTime, verifyExpiryTime, err := a.getVerificationSettings()
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionGet, "email verification settings", nil, err)
	}
	//check if email verification is off
	if verifyWaitTime == nil || verifyExpiryTime == nil {
		verified := true
		return &verified, nil, nil
	}

	//it is unverified
	verified := false
	//check if the verification is expired
	storedCreds, err := a.mapToCreds(credential.Value)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionCast, typeEmailCreds, nil, err)
	}
	expired := false
	_, verificationExpiry := storedCreds.getVerificationParams()
	if verificationExpiry == nil || verificationExpiry.Before(time.Now()) {
		expired = true
	}
	return &verified, &expired, nil
}

func (a *emailIdentifierImpl) sendCode(identifier string, appName string, code string, codeType string, credID string) (string, error) {
	params := url.Values{}
	params.Add("id", credID)
	params.Add("code", code)
	switch codeType {
	case typePasswordResetCode:
		passwordResetLink := a.auth.host + fmt.Sprintf("/ui/credential/reset?%s", params.Encode())
		subject := "Reset your password"
		if appName != "" {
			subject += " for " + appName
		}
		body := "Please click the link below to reset your password:<br><a href=" + passwordResetLink + ">" + passwordResetLink + "</a><br><br>If you did not request a password reset, please ignore this message."
		return "", a.auth.emailer.Send(identifier, subject, body, nil)
	case typeVerificationCode:
		verificationLink := a.auth.host + fmt.Sprintf("/ui/credential/verify?%s", params.Encode())
		subject := "Verify your email address"
		if appName != "" {
			subject += " for " + appName
		}
		body := "Please click the link below to verify your email address:<br><a href=" + verificationLink + ">" + verificationLink + "</a><br><br>If you did not request this verification link, please ignore this message."
		return "", a.auth.emailer.Send(identifier, subject, body, nil)
	//TODO: typeAuthenticationCode
	default:
		return "", errors.ErrorData(logutils.StatusInvalid, "code type", logutils.StringArgs(codeType))
	}
}

// Helpers

func (a *emailIdentifierImpl) getVerificationSettings() (*int, *int, error) {
	authType, err := a.auth.storage.FindAuthType(a.identifierType)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthType, logutils.StringArgs(a.identifierType), err)
	}
	if authType == nil {
		return nil, nil, errors.ErrorData(logutils.StatusMissing, model.TypeAuthType, logutils.StringArgs(a.identifierType))
	}

	// Should email addresses be verified (default is true)
	shouldVerify, ok := authType.Params["verify_email"].(bool)
	if ok && !shouldVerify {
		return nil, nil, nil
	}

	// Time in seconds to wait before sending another auth code (default is 30)
	verifyWaitTime := 30
	verifyWaitTimeParam, ok := authType.Params["verify_wait_time"].(int)
	if ok {
		verifyWaitTime = verifyWaitTimeParam
	}

	// Time in hours before auth code expires (default is 24)
	verifyExpiry := 24
	verifyExpiryParam, ok := authType.Params["verify_expiry"].(int)
	if ok {
		verifyExpiry = verifyExpiryParam
	}

	return &verifyWaitTime, &verifyExpiry, nil
}

// initEmailIdentifier initializes and registers a new email identifier instance
func initEmailIdentifier(auth *Auth) (*emailIdentifierImpl, error) {
	email := &emailIdentifierImpl{auth: auth, identifierType: IdentifierTypeEmail}

	err := auth.registerIdentifierType(email.identifierType, email)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeIdentifierType, nil, err)
	}

	return email, nil
}
