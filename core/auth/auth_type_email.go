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
	"github.com/rokwire/logging-library-go/v2/logs"
	"github.com/rokwire/logging-library-go/v2/logutils"
	"golang.org/x/crypto/bcrypt"
)

const (
	//AuthTypeEmail email auth type
	AuthTypeEmail string = "email"

	typeTime        logutils.MessageDataType = "time.Time"
	typeEmailCreds  logutils.MessageDataType = "email creds"
	typeEmailParams logutils.MessageDataType = "email params"
)

// enailCreds represents the creds struct for email auth
type emailCreds struct {
	Email              string    `json:"email" bson:"email" validate:"required"`
	Password           string    `json:"password" bson:"password"`
	VerificationCode   string    `json:"verification_code" bson:"verification_code"`
	VerificationExpiry time.Time `json:"verification_expiry" bson:"verification_expiry"`
	ResetCode          string    `json:"reset_code" bson:"reset_code"`
	ResetExpiry        time.Time `json:"reset_expiry" bson:"reset_expiry"`
}

// Email implementation of authType
type emailAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *emailAuthImpl) signUp(authType model.AuthType, appOrg model.ApplicationOrganization, creds string, params string, newCredentialID string, l *logs.Log) (string, map[string]interface{}, error) {
	type signUpEmailParams struct {
		ConfirmPassword string `json:"confirm_password"`
	}

	var sEmailCreds emailCreds
	err := json.Unmarshal([]byte(creds), &sEmailCreds)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeEmailCreds, nil, err)
	}

	var sEmailParams signUpEmailParams
	err = json.Unmarshal([]byte(params), &sEmailParams)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeEmailParams, nil, err)
	}

	email := sEmailCreds.Email
	password := sEmailCreds.Password
	confirmPassword := sEmailParams.ConfirmPassword
	if len(email) == 0 {
		return "", nil, errors.ErrorData(logutils.StatusMissing, typeEmailCreds, logutils.StringArgs("email"))
	}
	if len(password) == 0 {
		return "", nil, errors.ErrorData(logutils.StatusMissing, typeEmailCreds, logutils.StringArgs("password"))
	}
	if len(confirmPassword) == 0 {
		return "", nil, errors.ErrorData(logutils.StatusMissing, typeEmailParams, logutils.StringArgs("confirm_password"))
	}
	//check if the passwrod matches with the confirm password one
	if password != confirmPassword {
		return "", nil, errors.ErrorData(logutils.StatusInvalid, "mismatching password fields", nil)
	}

	emailCreds, err := a.buildCredentials(authType, appOrg.Application.Name, email, password, newCredentialID)
	if err != nil {
		return "", nil, errors.WrapErrorAction("building", "email credentials", nil, err)
	}

	return "verification code sent successfully", emailCreds, nil
}

func (a *emailAuthImpl) signUpAdmin(authType model.AuthType, appOrg model.ApplicationOrganization, identifier string, password string, newCredentialID string) (map[string]interface{}, map[string]interface{}, error) {
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

func (a *emailAuthImpl) isCredentialVerified(credential *model.Credential, l *logs.Log) (*bool, *bool, error) {
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

func (a *emailAuthImpl) checkCredentials(accountAuthType model.AccountAuthType, creds string, l *logs.Log) (string, error) {
	//get stored credential
	storedCreds, err := mapToEmailCreds(accountAuthType.Credential.Value)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionCast, typeEmailCreds, nil, err)
	}

	//get request credential
	type signInPasswordCred struct {
		Password string `json:"password"`
	}
	var sPasswordParams signInPasswordCred
	err = json.Unmarshal([]byte(creds), &sPasswordParams)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, "sign in password creds", nil, err)
	}
	requestPassword := sPasswordParams.Password

	//compare stored and requets ones
	err = bcrypt.CompareHashAndPassword([]byte(storedCreds.Password), []byte(requestPassword))
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionValidate, model.TypeCredential, nil, err).SetStatus(utils.ErrorStatusInvalid)
	}

	return "", nil
}

func (a *emailAuthImpl) buildCredentials(authType model.AuthType, appName string, email string, password string, credID string) (map[string]interface{}, error) {
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

func (a *emailAuthImpl) getVerifyEmail(authType model.AuthType) bool {
	verifyEmail := true
	verifyEmailParam, ok := authType.Params["verify_email"].(bool)
	if ok {
		verifyEmail = verifyEmailParam
	}
	return verifyEmail
}

// Time in seconds to wait before sending another verification email
func (a *emailAuthImpl) getVerifyWaitTime(authType model.AuthType) int {
	//Default is 30 seconds
	verifyWaitTime := 30
	verifyWaitTimeParam, ok := authType.Params["verify_wait_time"].(int)
	if ok {
		verifyWaitTime = verifyWaitTimeParam
	}
	return verifyWaitTime
}

// Time in hours before verification code expires
func (a *emailAuthImpl) getVerifyExpiry(authType model.AuthType) int {
	//Default is 24 hours
	verifyExpiry := 24
	verifyExpiryParam, ok := authType.Params["verify_expiry"].(int)
	if ok {
		verifyExpiry = verifyExpiryParam
	}
	return verifyExpiry
}

func (a *emailAuthImpl) sendVerificationCode(email string, appName string, verificationCode string, credentialID string) error {
	params := url.Values{}
	params.Add("id", credentialID)
	params.Add("code", verificationCode)
	verificationLink := a.auth.host + fmt.Sprintf("/ui/credential/verify?%s", params.Encode())
	subject := "Verify your email address"
	if appName != "" {
		subject += " for " + appName
	}
	body := "Please click the link below to verify your email address:<br><a href=" + verificationLink + ">" + verificationLink + "</a><br><br>If you did not request this verification link, please ignore this message."
	return a.auth.emailer.Send(email, subject, body, nil)
}

func (a *emailAuthImpl) sendPasswordResetEmail(credentialID string, resetCode string, email string, appName string) error {
	params := url.Values{}
	params.Add("id", credentialID)
	params.Add("code", resetCode)
	passwordResetLink := a.auth.host + fmt.Sprintf("/ui/credential/reset?%s", params.Encode())
	subject := "Reset your password"
	if appName != "" {
		subject += " for " + appName
	}
	body := "Please click the link below to reset your password:<br><a href=" + passwordResetLink + ">" + passwordResetLink + "</a><br><br>If you did not request a password reset, please ignore this message."
	return a.auth.emailer.Send(email, subject, body, nil)
}

func (a *emailAuthImpl) verifyCredential(credential *model.Credential, verification string, l *logs.Log) (map[string]interface{}, error) {
	credBytes, err := json.Marshal(credential.Value)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typeEmailCreds, nil, err)
	}

	var creds *emailCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeEmailCreds, nil, err)
	}
	err = a.compareCode(creds.VerificationCode, verification, creds.VerificationExpiry, l)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, model.TypeAuthCred, &logutils.FieldArgs{"verification_code": verification}, err)
	}

	//Update verification data
	creds.VerificationCode = ""
	creds.VerificationExpiry = time.Time{}
	credsMap, err := emailCredsToMap(creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, typeEmailCreds, nil, err)
	}

	return credsMap, nil
}

func (a *emailAuthImpl) sendVerifyCredential(credential *model.Credential, appName string, l *logs.Log) error {
	//Check if verify email is disabled for the given authType
	authType := credential.AuthType
	verifyEmail := a.getVerifyEmail(authType)
	if !verifyEmail {
		return errors.ErrorAction(logutils.ActionSend, logutils.TypeString, logutils.StringArgs("verify email is disabled for authType"))
	}
	verifyWaitTime := a.getVerifyWaitTime(authType)
	verifyExpiryTime := a.getVerifyExpiry(authType)

	//Parse credential value to emailCreds
	emailCreds, err := mapToEmailCreds(credential.Value)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCast, typeEmailCreds, nil, err)
	}
	//Check if previous verification email was sent less than 30 seconds ago
	now := time.Now()
	prevTime := emailCreds.VerificationExpiry.Add(time.Duration(-verifyExpiryTime) * time.Hour)
	if now.Sub(prevTime) < time.Duration(verifyWaitTime)*time.Second {
		return errors.ErrorAction(logutils.ActionSend, "verify code", logutils.StringArgs("resend requested too soon"))
	}
	//verification code
	code, err := utils.GenerateRandomString(64)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionGenerate, "verification code", nil, err)
	}

	//send verification email
	if err = a.sendVerificationCode(emailCreds.Email, appName, code, credential.ID); err != nil {
		return errors.WrapErrorAction(logutils.ActionSend, "verification email", nil, err)
	}

	//Update verification data in credential value
	emailCreds.VerificationCode = code
	emailCreds.VerificationExpiry = time.Now().Add(time.Hour * time.Duration(verifyExpiryTime))
	credsMap, err := emailCredsToMap(emailCreds)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCast, "map from email creds", nil, err)
	}

	credential.Value = credsMap
	if err = a.auth.storage.UpdateCredential(nil, credential); err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
	}

	return nil
}

func (a *emailAuthImpl) restartCredentialVerification(credential *model.Credential, appName string, l *logs.Log) error {
	storedCreds, err := mapToEmailCreds(credential.Value)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCast, typeEmailCreds, nil, err)
	}
	//Generate new verification code
	newCode, err := utils.GenerateRandomString(64)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionGenerate, "verification code", nil, err)

	}
	//send new verification code for future
	if err = a.sendVerificationCode(storedCreds.Email, appName, newCode, credential.ID); err != nil {
		return errors.WrapErrorAction(logutils.ActionSend, "verification email", nil, err)
	}
	//update new verification data in credential value
	storedCreds.VerificationCode = newCode
	storedCreds.VerificationExpiry = time.Now().Add(time.Hour * 24)
	emailCredValueMap, err := emailCredsToMap(storedCreds)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCast, "map from email creds", nil, err)
	}

	err = a.auth.storage.UpdateCredentialValue(credential.ID, emailCredValueMap)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
	}
	return nil
}

func (a *emailAuthImpl) compareCode(credCode string, requestCode string, expiryTime time.Time, l *logs.Log) error {
	if expiryTime.Before(time.Now()) {
		return errors.ErrorData("expired", "code", nil)
	}

	if subtle.ConstantTimeCompare([]byte(credCode), []byte(requestCode)) == 0 {
		return errors.ErrorData(logutils.StatusInvalid, "code", nil)
	}
	return nil
}

func (a *emailAuthImpl) resetCredential(credential *model.Credential, resetCode *string, params string, l *logs.Log) (map[string]interface{}, error) {
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

func (a *emailAuthImpl) forgotCredential(credential *model.Credential, identifier string, appName string, l *logs.Log) (map[string]interface{}, error) {
	emailCreds, err := mapToEmailCreds(credential.Value)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, typeEmailCreds, nil, err)
	}
	resetCode, err := utils.GenerateRandomString(64)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGenerate, "reset code", nil, err)

	}
	hashedResetCode, err := bcrypt.GenerateFromPassword([]byte(resetCode), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGenerate, "reset code hash", nil, err)
	}
	emailCreds.ResetCode = string(hashedResetCode)
	emailCreds.ResetExpiry = time.Now().Add(time.Hour * 24)
	err = a.sendPasswordResetEmail(credential.ID, resetCode, identifier, appName)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionSend, "password reset email", nil, err)
	}
	credsMap, err := emailCredsToMap(emailCreds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, "map from email creds", nil, err)
	}
	return credsMap, nil
}

func (a *emailAuthImpl) getUserIdentifier(creds string) (string, error) {
	var requestCreds emailCreds
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, typeEmailCreds, nil, err)
	}

	return requestCreds.Email, nil
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

// initEmailAuth initializes and registers a new email auth instance
func initEmailAuth(auth *Auth) (*emailAuthImpl, error) {
	email := &emailAuthImpl{auth: auth, authType: AuthTypeEmail}

	err := auth.registerAuthType(email.authType, email)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAuthType, nil, err)
	}

	return email, nil
}
