// Copyright 2023 Board of Trustees of the University of Illinois.
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

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logs"
	"github.com/rokwire/logging-library-go/v2/logutils"
	"golang.org/x/crypto/bcrypt"
)

const (
	//VerificationTypePassword password verification type
	VerificationTypePassword string = "password"
)

type signInCreds struct {
	Password string `json:"password"`
}

type signUpParams struct {
	ConfirmPassword string `json:"confirm_password"`
}

func (p *signUpParams) credential() string {
	return p.ConfirmPassword
}

// Password implementation of verificationType
type passwordVerificationImpl struct {
	auth             *Auth
	verificationType string
}

func (a *passwordVerificationImpl) parseCreds(creds string, credential verificationCreds) error {
	err := json.Unmarshal([]byte(creds), credential)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUnmarshal, typeVerificationCreds, nil, err)
	}

	if len(credential.identifier()) == 0 {
		return errors.ErrorData(logutils.StatusMissing, typeVerificationCreds, logutils.StringArgs("identifier"))
	}
	if len(credential.credential()) == 0 {
		return errors.ErrorData(logutils.StatusMissing, typeVerificationCreds, logutils.StringArgs("credential"))
	}

	return nil
}

func (a *passwordVerificationImpl) parseParams(params string, parameter verificationParams) error {
	err := json.Unmarshal([]byte(params), parameter)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUnmarshal, typeVerificationParams, nil, err)
	}

	if len(parameter.credential()) == 0 {
		return errors.ErrorData(logutils.StatusMissing, typeVerificationParams, logutils.StringArgs("credential"))
	}

	return nil
}

func (a *passwordVerificationImpl) checkCredentials(accountAuthType model.AccountAuthType, creds string, credential verificationCreds, l *logs.Log) (string, error) {
	//get stored credential
	credBytes, err := json.Marshal(accountAuthType.Credential.Value)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionMarshal, typeVerificationCreds, nil, err)
	}
	var verifyCreds verificationCreds
	err = json.Unmarshal(credBytes, verifyCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, typeVerificationCreds, nil, err)
	}

	//get request credential
	var sPasswordCreds signInCreds
	err = json.Unmarshal([]byte(creds), &sPasswordCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, "sign in password creds", nil, err)
	}

	//compare stored and requets ones
	err = bcrypt.CompareHashAndPassword([]byte(verifyCreds.credential()), []byte(sPasswordCreds.Password))
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionValidate, model.TypeCredential, nil, err).SetStatus(utils.ErrorStatusInvalid)
	}

	return "", nil
}

// initPasswordVerification initializes and registers a new password verification instance
func initPasswordVerification(auth *Auth) (*passwordVerificationImpl, error) {
	password := &passwordVerificationImpl{auth: auth, verificationType: VerificationTypePassword}

	err := auth.registerVerificationType(password.verificationType, password)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeVerificationType, nil, err)
	}

	return password, nil
}
