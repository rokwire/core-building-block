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
	"time"

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
	"golang.org/x/crypto/bcrypt"
)

const (
	//AuthTypePassword password auth type
	AuthTypePassword string = "password"

	typePasswordResetCode string = "password reset code"

	typePasswordResetParams logutils.MessageDataType = "password reset params"
)

type passwordResetParams struct {
	NewPassword     string `json:"new_password"`
	ConfirmPassword string `json:"confirm_password"`
}

// Password implementation of authType
type passwordAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *passwordAuthImpl) signUp(identifierImpl identifierType, appName string, creds string, params string, newCredentialID string) (string, map[string]interface{}, error) {
	passwordCreds, err := identifierImpl.parseCreds(creds)
	if err != nil {
		return "", nil, errors.ErrorData(logutils.StatusInvalid, "password creds", nil)
	}

	passwordParams, err := identifierImpl.parseParams(params)
	if err != nil {
		return "", nil, errors.ErrorData(logutils.StatusInvalid, "password params", nil)
	}

	credType, cred := passwordCreds.getCredential()
	if credType != AuthTypePassword {
		return "", nil, errors.ErrorData(logutils.StatusInvalid, "credential type", logutils.StringArgs(credType))
	}
	if passwordParams != nil {
		confirmCredType, confirmCred := passwordParams.parameter()
		if confirmCredType != AuthTypePassword {
			return "", nil, errors.ErrorData(logutils.StatusInvalid, "confirmation credential type", logutils.StringArgs(confirmCredType))
		}
		if cred != confirmCred {
			return "", nil, errors.ErrorData(logutils.StatusInvalid, "mismatching credentials", nil)
		}
	}

	message, credsMap, err := a.generateCredential(identifierImpl, appName, passwordCreds.identifier(), cred, newCredentialID)
	if err != nil {
		return "", nil, errors.WrapErrorAction("building", "password credentials", nil, err)
	}

	return message, credsMap, nil
}

func (a *passwordAuthImpl) signUpAdmin(identifierImpl identifierType, appName string, identifier string, credential string, newCredentialID string) (map[string]interface{}, map[string]interface{}, error) {
	if credential == "" {
		credential = utils.GenerateRandomPassword(12)
	}

	_, creds, err := a.generateCredential(identifierImpl, appName, identifier, credential, newCredentialID)
	if err != nil {
		return nil, nil, errors.WrapErrorAction("building", "password credentials", nil, err)
	}

	params := map[string]interface{}{"password": credential}
	return params, creds, nil
}

func (a *passwordAuthImpl) forgotCredential(identifierImpl identifierType, credential authCreds, appName string, credID string) (map[string]interface{}, error) {
	//TODO: turn length of reset code into a setting
	resetCode, err := utils.GenerateRandomString(64)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGenerate, "reset code", nil, err)

	}
	hashedResetCode, err := bcrypt.GenerateFromPassword([]byte(resetCode), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGenerate, "reset code hash", nil, err)
	}

	resetExpiry := time.Now().Add(time.Hour * 24)
	credential.setResetParams(string(hashedResetCode), &resetExpiry)
	_, err = identifierImpl.sendCode(credential.identifier(), appName, resetCode, typePasswordResetCode, credID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionSend, "password reset code", nil, err)
	}
	credsMap, err := credential.toMap()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, "map from creds", nil, err)
	}
	return credsMap, nil
}

func (a *passwordAuthImpl) resetCredential(credential authCreds, resetCode *string, params string) (map[string]interface{}, error) {
	var resetData passwordResetParams
	err := json.Unmarshal([]byte(params), &resetData)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePasswordResetParams, nil, err)
	}

	if len(resetData.NewPassword) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, logutils.TypeString, logutils.StringArgs("new password"))
	}
	if len(resetData.ConfirmPassword) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, logutils.TypeString, logutils.StringArgs("confirm password"))
	}
	//check if the password matches with the confirm password one
	if resetData.NewPassword != resetData.ConfirmPassword {
		return nil, errors.ErrorData(logutils.StatusInvalid, "mismatching password reset fields", nil)
	}

	//reset password from link
	if resetCode != nil {
		storedResetCode, storedResetExpiry := credential.getResetParams()
		if storedResetExpiry == nil || storedResetExpiry.Before(time.Now()) {
			return nil, errors.ErrorData("expired", "reset expiration time", nil)
		}
		err = bcrypt.CompareHashAndPassword([]byte(storedResetCode), []byte(*resetCode))
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionValidate, "password reset code", nil, err)
		}

		//Update verification data
		credential.setResetParams("", nil)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(resetData.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGenerate, "password hash", nil, err)
	}

	//Update verification data
	credential.setCredential(string(hashedPassword), AuthTypePassword)
	credsMap, err := credential.toMap()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, "map from password creds", nil, err)
	}

	return credsMap, nil
}

func (a *passwordAuthImpl) checkCredential(identifierImpl identifierType, storedCreds authCreds, incomingCreds authCreds, appName string, credID string) (string, error) {
	storedCredType, storedCred := storedCreds.getCredential()
	incomingCredType, incomingCred := incomingCreds.getCredential()
	if storedCredType != AuthTypePassword || incomingCredType != AuthTypePassword {
		return "", errors.ErrorData(logutils.StatusInvalid, "mismatching credential types", nil)
	}

	//compare stored and requets ones
	err := bcrypt.CompareHashAndPassword([]byte(storedCred), []byte(incomingCred))
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionValidate, model.TypeCredential, nil, err).SetStatus(utils.ErrorStatusInvalid)
	}

	return "", nil
}

// Helpers

func (a *passwordAuthImpl) generateCredential(identifierImpl identifierType, appName string, identifier string, password string, credID string) (string, map[string]interface{}, error) {
	//password hash
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionGenerate, "password hash", nil, err)
	}

	message := ""
	credValue := identifierImpl.buildCredential(identifier, string(hashedPassword), AuthTypePassword)
	credValueMap, sent, err := identifierImpl.sendVerifyCredential(credValue, appName, credID)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionSend, "identifier verification", nil, err)
	}

	if sent {
		message = "verification code sent successfully"
	}

	return message, credValueMap, nil
}

// initPasswordAuth initializes and registers a new password auth instance
func initPasswordAuth(auth *Auth) (*passwordAuthImpl, error) {
	password := &passwordAuthImpl{auth: auth, authType: AuthTypePassword}

	err := auth.registerAuthType(password.authType, password)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAuthType, nil, err)
	}

	return password, nil
}
