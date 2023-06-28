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
	"context"
	"core-building-block/core/model"
	"core-building-block/utils"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logs"
	"github.com/rokwire/logging-library-go/v2/logutils"
	"golang.org/x/crypto/bcrypt"
)

const (
	//VerificationTypeCode code verification type
	VerificationTypeCode string = "code"
)

// Code implementation of verificationType
type codeVerificationImpl struct {
	auth             *Auth
	verificationType string
}

type verifyPhoneResponse struct {
	Status      string      `json:"status"`
	Payee       interface{} `json:"payee"`
	DateUpdated time.Time   `json:"date_updated"`
	AccountSid  string      `json:"account_sid"`
	To          string      `json:"to"`
	Amount      interface{} `json:"amount"`
	Valid       bool        `json:"valid"`
	URL         string      `json:"url"`
	Sid         string      `json:"sid"`
	DateCreated time.Time   `json:"date_created"`
	ServiceSid  string      `json:"service_sid"`
	Channel     string      `json:"channel"`
}

type checkStatusResponse struct {
	Sid         string      `json:"sid"`
	ServiceSid  string      `json:"service_sid"`
	AccountSid  string      `json:"account_sid"`
	To          string      `json:"to" validate:"required"`
	Channel     string      `json:"channel"`
	Status      string      `json:"status"`
	Amount      interface{} `json:"amount"`
	Payee       interface{} `json:"payee"`
	DateCreated time.Time   `json:"date_created"`
	DateUpdated time.Time   `json:"date_updated"`
}

func (a *codeVerificationImpl) verifyCredential(credential authCreds, verification string) (map[string]interface{}, error) {
	verificationCode, verificationExpiry := credential.getVerificationParams()
	if verificationExpiry == nil || verificationExpiry.Before(time.Now()) {
		return nil, errors.ErrorData("expired", "credential verification code", nil)
	}
	if subtle.ConstantTimeCompare([]byte(verificationCode), []byte(verification)) == 0 {
		return nil, errors.ErrorData(logutils.StatusInvalid, "credential verification code", nil)
	}

	//Update verification data
	credential.setVerificationParams("", nil)
	credsMap, err := credential.toMap()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, "map from creds", nil, err)
	}

	return credsMap, nil
}

func (a *codeVerificationImpl) sendVerifyCredential(credential *model.Credential, appName string, l *logs.Log) error {
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

func (a *codeVerificationImpl) sendVerifyOnSignup(identifierImpl identifierType, identifier string, appName string, credID string) (string, *time.Time, error) {
	//verification code
	code, err := utils.GenerateRandomString(64)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionGenerate, "verification code", nil, err)
	}

	verificationExpiry := time.Now().Add(time.Hour * time.Duration(identifierImpl.getVerifyExpiry(authType)))

	//send verification code
	if err = identifierImpl.sendVerificationCode(identifier, appName, code, credID); err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionSend, "verification email", nil, err)
	}

	return code, &verificationExpiry, nil
}

func (a *codeVerificationImpl) restartCredentialVerification(credential *model.Credential, appName string, l *logs.Log) error {
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

func (a *codeVerificationImpl) sendVerificationCode(email string, appName string, verificationCode string, credentialID string) error {
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

// func (a *codeVerificationImpl) compareCode(credCode string, requestCode string, expiryTime time.Time) error {

// 	return nil
// }

func (a *codeVerificationImpl) forgotCredential(credential *model.Credential, identifier string, appName string, l *logs.Log) (map[string]interface{}, error) {
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

func (a *codeVerificationImpl) sendPasswordResetEmail(credentialID string, resetCode string, email string, appName string) error {
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

func (a *codeVerificationImpl) handlePhoneVerify(phone string, verificationCreds twilioPhoneCreds, l *logs.Log) (string, error) {
	if a.twilioAccountSID == "" {
		return "", errors.ErrorData(logutils.StatusMissing, typeVerifyServiceID, nil)
	}

	if a.twilioToken == "" {
		return "", errors.ErrorData(logutils.StatusMissing, typeVerifyServiceToken, nil)
	}

	data := url.Values{}
	data.Add("To", phone)
	if verificationCreds.Code != "" {
		// check verification
		data.Add("Code", verificationCreds.Code)
		return "", a.checkVerification(phone, data, l)
	}

	// start verification
	data.Add("Channel", "sms")

	message := ""
	err := a.startVerification(phone, data, l)
	if err == nil {
		message = "verification code sent successfully"
	}
	return message, err
}

func (a *codeVerificationImpl) startVerification(phone string, data url.Values, l *logs.Log) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body, err := makeRequest(ctx, "POST", servicesPathPart+"/"+a.twilioServiceSID+"/"+verificationsPathPart, data, a.twilioAccountSID, a.twilioToken)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSend, logutils.TypeRequest, &logutils.FieldArgs{"verification params": data}, err)
	}

	var verifyResult verifyPhoneResponse
	err = json.Unmarshal(body, &verifyResult)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUnmarshal, typeVerificationResponse, nil, err)
	}

	if verifyResult.To != phone {
		return errors.ErrorData(logutils.StatusInvalid, logutils.TypeString, &logutils.FieldArgs{"expected phone": phone, "actual phone": verifyResult.To})
	}
	if verifyResult.Status != "pending" {
		return errors.ErrorData(logutils.StatusInvalid, typeVerificationStatus, &logutils.FieldArgs{"expected pending, actual:": verifyResult.Status})
	}
	if verifyResult.Sid == "" {
		return errors.ErrorData(logutils.StatusMissing, typeVerificationSID, nil)
	}

	return nil
}

func (a *codeVerificationImpl) checkVerification(phone string, data url.Values, l *logs.Log) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	body, err := makeRequest(ctx, "POST", servicesPathPart+"/"+a.twilioServiceSID+"/"+verificationCheckPart, data, a.twilioAccountSID, a.twilioToken)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSend, logutils.TypeRequest, nil, err)
	}

	var checkResponse checkStatusResponse
	err = json.Unmarshal(body, &checkResponse)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUnmarshal, typeVerificationResponse, nil, err)
	}

	if checkResponse.To != phone {
		return errors.ErrorData(logutils.StatusInvalid, logutils.TypeString, &logutils.FieldArgs{"expected phone": phone, "actual phone": checkResponse.To})
	}
	if checkResponse.Status != "approved" {
		return errors.ErrorData(logutils.StatusInvalid, typeVerificationStatus, &logutils.FieldArgs{"expected approved, actual:": checkResponse.Status}).SetStatus(utils.ErrorStatusInvalid)
	}

	return nil
}

func makeRequest(ctx context.Context, method string, pathPart string, data url.Values, user string, token string) ([]byte, error) {
	client := &http.Client{}
	rb := new(strings.Reader)
	logAction := logutils.ActionSend

	if data != nil && (method == "POST" || method == "PUT") {
		rb = strings.NewReader(data.Encode())
	}
	if method == "GET" && data != nil {
		pathPart = pathPart + "?" + data.Encode()
		logAction = logutils.ActionRead
	}

	req, err := http.NewRequest(method, pathPart, rb)
	if err != nil {
		return nil, errors.WrapErrorAction(logAction, logutils.TypeRequest, &logutils.FieldArgs{"path": pathPart}, err)
	}

	if token != "" {
		req.Header.Add("Authorization", "Basic "+basicAuth(user, token))
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.WrapErrorAction(logAction, logutils.TypeRequest, nil, err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err)
	}
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return nil, errors.ErrorData(logutils.StatusInvalid, logutils.TypeResponse, &logutils.FieldArgs{"status_code": resp.StatusCode, "error": string(body)})
	}
	return body, nil
}

func basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
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

// initCodeVerification initializes and registers a new code verification instance
func initCodeVerification(auth *Auth) (*codeVerificationImpl, error) {
	code := &codeVerificationImpl{auth: auth, verificationType: VerificationTypeCode}

	err := auth.registerVerificationType(code.verificationType, code)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeVerificationType, nil, err)
	}

	return code, nil
}
