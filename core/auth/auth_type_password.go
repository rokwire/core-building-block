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
	"regexp"
	"time"

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logs"
	"github.com/rokwire/logging-library-go/v2/logutils"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/go-playground/validator.v9"
)

const (
	//AuthTypePassword password auth type
	AuthTypePassword string = "password"
)

type passwordCreds struct {
	Password string `json:"password"`
}

type passwordParams struct {
	ConfirmPassword string `json:"confirm_password"`
}

func (p *passwordParams) credential() string {
	return p.ConfirmPassword
}

// Password implementation of authType
type passwordAuthImpl struct {
	auth     *Auth
	authType string
}

func emailCredsToMap(creds *emailCreds) (map[string]interface{}, error) {
	credBytes, err := json.Marshal(creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typeEmailCreds, nil, err)
	}
	var credsMap map[string]interface{}
	err = json.Unmarshal(credBytes, &credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, "map from email creds", nil, err)
	}
	return credsMap, nil
}

func mapToEmailCreds(credsMap map[string]interface{}) (*emailCreds, error) {
	credBytes, err := json.Marshal(credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typeEmailCreds, nil, err)
	}
	var creds emailCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeEmailCreds, nil, err)
	}
	return &creds, nil
}

func usernameCredsToMap(creds *usernameCreds) (map[string]interface{}, error) {
	credBytes, err := json.Marshal(creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typeUsernameCreds, nil, err)
	}
	var credsMap map[string]interface{}
	err = json.Unmarshal(credBytes, &credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, "map from username creds", nil, err)
	}
	return credsMap, nil
}

func mapToUsernameCreds(credsMap map[string]interface{}) (*usernameCreds, error) {
	credBytes, err := json.Marshal(credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typeUsernameCreds, nil, err)
	}
	var creds usernameCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeUsernameCreds, nil, err)
	}
	return &creds, nil
}

func (a *twilioPhoneAuthImpl) checkRequestCreds(creds string) (*twilioPhoneCreds, error) {
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

func (a *passwordAuthImpl) parseCreds(creds string, credential authCreds) error {
	err := json.Unmarshal([]byte(creds), credential)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUnmarshal, typeAuthCreds, nil, err)
	}

	if len(credential.identifier()) == 0 {
		return errors.ErrorData(logutils.StatusMissing, typeAuthCreds, logutils.StringArgs("identifier"))
	}
	if len(credential.credential()) == 0 {
		return errors.ErrorData(logutils.StatusMissing, typeAuthCreds, logutils.StringArgs("credential"))
	}

	return nil
}

func (a *passwordAuthImpl) parseParams(params string, parameter authParams) error {
	err := json.Unmarshal([]byte(params), parameter)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUnmarshal, typeAuthParams, nil, err)
	}

	if len(parameter.credential()) == 0 {
		return errors.ErrorData(logutils.StatusMissing, typeAuthParams, logutils.StringArgs("credential"))
	}

	return nil
}

// Email
// Username

func (a *passwordAuthImpl) signUp(verificationImpl verificationType, authType model.AuthType, appOrg model.ApplicationOrganization, creds string, params string, newCredentialID string, l *logs.Log) (string, map[string]interface{}, error) {
	var sEmailCreds emailCreds
	err := verificationImpl.parseCreds(creds, &sEmailCreds)

	var sEmailParams signUpParams
	err = verificationImpl.parseParams(creds, &sEmailParams)

	//check if credentials match
	if sEmailCreds.credential() != sEmailParams.credential() {
		return "", nil, errors.ErrorData(logutils.StatusInvalid, "mismatching credentials", nil)
	}

	emailCreds, err := a.buildCredentials(authType, appOrg.Application.Name, sEmailCreds.identifier(), sEmailCreds.credential(), newCredentialID)
	if err != nil {
		return "", nil, errors.WrapErrorAction("building", "email credentials", nil, err)
	}

	return "verification code sent successfully", emailCreds, nil
}

func (a *passwordAuthImpl) signUp(verificationImpl verificationType, authType model.AuthType, appOrg model.ApplicationOrganization, creds string, params string, newCredentialID string, l *logs.Log) (string, map[string]interface{}, error) {
	var sUsernameCreds usernameCreds
	err := verificationImpl.parseCreds(creds, &sUsernameCreds)

	var sUsernameParams signUpParams
	err = verificationImpl.parseParams(creds, &sUsernameParams)

	//check if credentials match
	if sUsernameCreds.credential() != sUsernameParams.credential() {
		return "", nil, errors.ErrorData(logutils.StatusInvalid, "mismatching credentials", nil)
	}

	usernameCreds, err := a.buildCredentials(authType, appOrg.Application.Name, sUsernameCreds.identifier(), sUsernameCreds.credential(), newCredentialID)
	if err != nil {
		return "", nil, errors.WrapErrorAction("building", "username credentials", nil, err)
	}

	return "", usernameCreds, nil
}

// auth type code
func (a *passwordAuthImpl) signUp(authType model.AuthType, appOrg model.ApplicationOrganization, creds string, params string, newCredentialID string, l *logs.Log) (string, map[string]interface{}, error) {
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

func (a *passwordAuthImpl) signUpAdmin(authType model.AuthType, appOrg model.ApplicationOrganization, identifier string, password string, newCredentialID string) (map[string]interface{}, map[string]interface{}, error) {
	if password == "" {
		password = utils.GenerateRandomPassword(12)
	}

	emailCreds, err := a.buildCredentials(authType, appOrg.Application.Name, identifier, password, newCredentialID)
	if err != nil {
		return nil, nil, errors.WrapErrorAction("building", "email credentials", nil, err)
	}

	params := map[string]interface{}{"password": password}
	return params, emailCreds, nil
}

func (a *passwordAuthImpl) signUpAdmin(authType model.AuthType, appOrg model.ApplicationOrganization, identifier string, password string, newCredentialID string) (map[string]interface{}, map[string]interface{}, error) {
	if password == "" {
		password = utils.GenerateRandomPassword(12)
	}

	usernameCreds, err := a.buildCredentials(authType, appOrg.Application.Name, identifier, password, newCredentialID)
	if err != nil {
		return nil, nil, errors.WrapErrorAction("building", "username credentials", nil, err)
	}

	params := map[string]interface{}{"password": password}
	return params, usernameCreds, nil
}

func (a *passwordAuthImpl) isCredentialVerified(credential *model.Credential, l *logs.Log) (*bool, *bool, error) {
	if credential.Verified {
		verified := true
		return &verified, nil, nil
	}

	//check if email verification is off
	verifyEmail := a.getVerifyEmail(credential.AuthType)
	if !verifyEmail {
		verified := true
		return &verified, nil, nil
	}

	//it is unverified
	verified := false
	//check if the verification is expired
	storedCreds, err := mapToEmailCreds(credential.Value)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionCast, typeEmailCreds, nil, err)
	}
	expired := false
	if storedCreds.VerificationExpiry.Before(time.Now()) {
		expired = true
	}
	return &verified, &expired, nil
}

func (a *passwordAuthImpl) isCredentialVerified(credential *model.Credential, l *logs.Log) (*bool, *bool, error) {
	//TODO verification process for usernames
	verified := true
	expired := false
	return &verified, &expired, nil
}

func (a *passwordAuthImpl) buildCredentials(authType model.AuthType, appName string, email string, password string, credID string) (map[string]interface{}, error) {
	//password hash
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGenerate, "password hash", nil, err)
	}

	//verification code
	code, err := utils.GenerateRandomString(64)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGenerate, "verification code", nil, err)
	}

	verifyEmail := a.getVerifyEmail(authType)
	verifyExpiryTime := a.getVerifyExpiry(authType)

	var emailCredValue emailCreds
	if verifyEmail {
		emailCredValue = emailCreds{Email: email, Password: string(hashedPassword), VerificationCode: code, VerificationExpiry: time.Now().Add(time.Hour * time.Duration(verifyExpiryTime))}
	} else {
		emailCredValue = emailCreds{Email: email, Password: string(hashedPassword)}
	}

	emailCredValueMap, err := emailCredsToMap(&emailCredValue)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, "map from email creds", nil, err)
	}

	if verifyEmail {
		//send verification code
		if err = a.sendVerificationCode(email, appName, code, credID); err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionSend, "verification email", nil, err)
		}
	}

	return emailCredValueMap, nil
}

func (a *passwordAuthImpl) buildCredentials(authType model.AuthType, appName string, username string, password string, credID string) (map[string]interface{}, error) {

	//password hash
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGenerate, "password hash", nil, err)
	}

	usernameCredValue := usernameCreds{Username: username, Password: string(hashedPassword)}

	usernameCredValueMap, err := usernameCredsToMap(&usernameCredValue)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, "map from username creds", nil, err)
	}

	return usernameCredValueMap, nil
}

func (a *passwordAuthImpl) resetCredential(credential *model.Credential, resetCode *string, params string, l *logs.Log) (map[string]interface{}, error) {
	//get the data from params
	type Params struct {
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
	}

	var paramsData Params
	err := json.Unmarshal([]byte(params), &paramsData)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeEmailParams, nil, err)
	}
	newPassword := paramsData.NewPassword
	confirmPassword := paramsData.ConfirmPassword

	if len(newPassword) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, logutils.TypeString, logutils.StringArgs("new_password"))
	}
	if len(confirmPassword) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, logutils.TypeString, logutils.StringArgs("confirm_password"))
	}
	//check if the password matches with the confirm password one
	if newPassword != confirmPassword {
		return nil, errors.ErrorData(logutils.StatusInvalid, "mismatching password fields", nil)
	}

	credBytes, err := json.Marshal(credential.Value)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typeEmailCreds, nil, err)
	}

	var creds *emailCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeEmailCreds, nil, err)
	}
	//reset password from link
	if resetCode != nil {
		if creds.ResetExpiry.Before(time.Now()) {
			return nil, errors.ErrorData("expired", "reset expiration time", nil)
		}
		err = bcrypt.CompareHashAndPassword([]byte(creds.ResetCode), []byte(*resetCode))
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeAuthCred, &logutils.FieldArgs{"reset_code": *resetCode}, err)
		}

		//Update verification data
		creds.ResetCode = ""
		creds.ResetExpiry = time.Time{}
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGenerate, "password hash", nil, err)
	}

	//Update verification data
	creds.Password = string(hashedPassword)
	credsMap, err := emailCredsToMap(creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, "map from email creds", nil, err)
	}

	return credsMap, nil
}

func (a *passwordAuthImpl) resetCredential(credential *model.Credential, resetCode *string, params string, l *logs.Log) (map[string]interface{}, error) {
	//get the data from params
	type Params struct {
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
	}

	var paramsData Params
	err := json.Unmarshal([]byte(params), &paramsData)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeUsernameParams, nil, err)
	}
	newPassword := paramsData.NewPassword
	confirmPassword := paramsData.ConfirmPassword

	if len(newPassword) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, logutils.TypeString, logutils.StringArgs("new_password"))
	}
	if len(confirmPassword) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, logutils.TypeString, logutils.StringArgs("confirm_password"))
	}
	//check if the password matches with the confirm password one
	if newPassword != confirmPassword {
		return nil, errors.ErrorData(logutils.StatusInvalid, "mismatching password fields", nil)
	}

	credBytes, err := json.Marshal(credential.Value)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typeUsernameCreds, nil, err)
	}

	var creds *usernameCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeUsernameCreds, nil, err)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGenerate, "password hash", nil, err)
	}

	//Update verification data
	creds.Password = string(hashedPassword)
	credsMap, err := usernameCredsToMap(creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, "map from username creds", nil, err)
	}

	return credsMap, nil
}

func (a *passwordAuthImpl) checkCredentials(accountAuthType model.AccountAuthType, creds string, credential authCreds, l *logs.Log) (string, error) {
	//get stored credential
	credBytes, err := json.Marshal(accountAuthType.Credential.Value)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionMarshal, typeAuthCreds, nil, err)
	}
	var verifyCreds authCreds
	err = json.Unmarshal(credBytes, verifyCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, typeAuthCreds, nil, err)
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

// Helpers

func (a *passwordAuthImpl) shouldVerifyIdentifier(authType model.AuthType) bool {
	verify := true
	verifyParam, ok := authType.Params["verify"].(bool)
	if ok {
		verify = verifyParam
	}
	return verify
}

// Time in seconds to wait before sending another auth code
func (a *passwordAuthImpl) getVerifyWaitTime(authType model.AuthType) int {
	//Default is 30 seconds
	verifyWaitTime := 30
	verifyWaitTimeParam, ok := authType.Params["verify_wait_time"].(int)
	if ok {
		verifyWaitTime = verifyWaitTimeParam
	}
	return verifyWaitTime
}

// Time in hours before auth code expires
func (a *passwordAuthImpl) getVerifyExpiry(authType model.AuthType) int {
	//Default is 24 hours
	verifyExpiry := 24
	verifyExpiryParam, ok := authType.Params["verify_expiry"].(int)
	if ok {
		verifyExpiry = verifyExpiryParam
	}
	return verifyExpiry
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
