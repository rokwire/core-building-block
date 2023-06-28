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
	VerificationCode   string     `json:"verification_code" bson:"verification_code"`
	VerificationExpiry *time.Time `json:"verification_expiry" bson:"verification_expiry"`
	ResetCode          string     `json:"reset_code" bson:"reset_code"`
	ResetExpiry        *time.Time `json:"reset_expiry" bson:"reset_expiry"`
}

func (c *emailCreds) identifier() string {
	return c.Email
}

func (c *emailCreds) getCredential() (string, string) {
	if c.Password != nil {
		return AuthTypePassword, *c.Password
	}
	return "", ""
}

func (c *emailCreds) setCredential(value string, credType string) {
	if credType == AuthTypePassword {
		c.Password = &value
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
}

func (p *emailParams) parameter() (string, string) {
	if p.ConfirmPassword != nil {
		return AuthTypePassword, *p.ConfirmPassword
	}
	return "", ""
}

// Email implementation of identifierType
type emailIdentifierImpl struct {
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
	if credType, cred := credential.getCredential(); len(credType) == 0 || len(cred) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, typeEmailCreds, logutils.StringArgs("credential"))
	}

	return &credential, nil
}

func (a *emailIdentifierImpl) parseParams(params string) (authParams, error) {
	var parameters emailParams
	err := json.Unmarshal([]byte(params), &parameters)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeEmailParams, nil, err)
	}

	if paramType, param := parameters.parameter(); len(paramType) == 0 || len(param) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, typeEmailParams, logutils.StringArgs("parameter"))
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

func (a *emailIdentifierImpl) buildCredential(identifier string, credential string, credType string) authCreds {
	if credType == AuthTypePassword {
		return &emailCreds{Email: identifier, Password: &credential}
	}
	return nil
}

func (a *emailIdentifierImpl) verificationType() string {
	//TODO: how to get verification type and params?
	// verify := true
	// verifyParam, ok := authType.Params["verify"].(bool)
	// if ok {
	// 	verify = verifyParam
	// }
	// return verify
	return VerificationTypeCode
}

// Helpers

// Time in seconds to wait before sending another auth code
func (a *emailIdentifierImpl) getVerifyWaitTime(authType model.AuthType) int {
	//Default is 30 seconds
	verifyWaitTime := 30
	verifyWaitTimeParam, ok := authType.Params["verify_wait_time"].(int)
	if ok {
		verifyWaitTime = verifyWaitTimeParam
	}
	return verifyWaitTime
}

// Time in hours before auth code expires
func (a *emailIdentifierImpl) getVerifyExpiry(authType model.AuthType) int {
	//Default is 24 hours
	verifyExpiry := 24
	verifyExpiryParam, ok := authType.Params["verify_expiry"].(int)
	if ok {
		verifyExpiry = verifyExpiryParam
	}
	return verifyExpiry
}

// initEmailIdentifier initializes and registers a new email identifier instance
func initEmailIdentifier(auth *Auth) (*emailIdentifierImpl, error) {
	email := &emailIdentifierImpl{identifierType: IdentifierTypeEmail}

	err := auth.registerIdentifierType(email.identifierType, email)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeIdentifierType, nil, err)
	}

	return email, nil
}
