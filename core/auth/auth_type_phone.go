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
	"context"
	"core-building-block/core/model"
	"core-building-block/utils"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
	"gopkg.in/go-playground/validator.v9"
)

const (
	//AuthTypeTwilioPhone phone auth type
	AuthTypeTwilioPhone string = "twilio_phone"

	servicesPathPart                                  = "https://verify.twilio.com/v2/Services"
	verificationsPathPart                             = "Verifications"
	verificationCheckPart                             = "VerificationCheck"
	typeVerifyServiceID      logutils.MessageDataType = "phone verification service id"
	typeVerifyServiceToken   logutils.MessageDataType = "phone verification service token"
	typeVerificationResponse logutils.MessageDataType = "phone verification response"
	typeVerificationStatus   logutils.MessageDataType = "phone verification staus"
	typeVerificationSID      logutils.MessageDataType = "phone verification sid"
	typePhoneCreds           logutils.MessageDataType = "phone creds"
	typePhoneNumber          logutils.MessageDataType = "E.164 phone number"
)

// Phone implementation of authType
type twilioPhoneAuthImpl struct {
	auth             *Auth
	authType         string
	twilioAccountSID string
	twilioToken      string
	twilioServiceSID string
}

type twilioPhoneCreds struct {
	Phone string `json:"phone" validate:"required"`
	Code  string `json:"code"`
	// TODO: Password?
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

func (a *twilioPhoneAuthImpl) code() string {
	return a.authType
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

func (a *twilioPhoneAuthImpl) signUp(appOrg model.ApplicationOrganization, creds string, params string, newCredentialID string, l *logs.Log) (string, map[string]interface{}, error) {
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

func (a *twilioPhoneAuthImpl) signUpAdmin(appOrg model.ApplicationOrganization, identifier string, password string, newCredentialID string) (map[string]interface{}, map[string]interface{}, error) {
	return nil, nil, nil
}

func (a *twilioPhoneAuthImpl) isCredentialVerified(appOrg model.ApplicationOrganization, credential *model.Credential, l *logs.Log) (bool, *bool, error) {
	return true, nil, nil
}

func (a *twilioPhoneAuthImpl) checkCredentials(accountAuthType model.AccountAuthType, creds string, l *logs.Log) (string, error) {
	requestCreds, err := a.checkRequestCreds(creds)
	if err != nil {
		return "", err
	}

	// existing user
	message, err := a.handlePhoneVerify(requestCreds.Phone, *requestCreds, l)
	if err != nil {
		return "", err
	}

	return message, nil
}

func (a *twilioPhoneAuthImpl) handlePhoneVerify(phone string, verificationCreds twilioPhoneCreds, l *logs.Log) (string, error) {
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

func (a *twilioPhoneAuthImpl) startVerification(phone string, data url.Values, l *logs.Log) error {
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

func (a *twilioPhoneAuthImpl) checkVerification(phone string, data url.Values, l *logs.Log) error {
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

func (a *twilioPhoneAuthImpl) getUserIdentifier(creds string) (string, error) {
	var requestCreds twilioPhoneCreds
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, typePhoneCreds, nil, err)
	}

	return requestCreds.Phone, nil
}

func (a *twilioPhoneAuthImpl) verifyCredential(credential *model.Credential, verification string, l *logs.Log) (map[string]interface{}, error) {
	return nil, errors.New(logutils.Unimplemented)
}

func (a *twilioPhoneAuthImpl) sendVerifyCredential(appOrg model.ApplicationOrganization, credential *model.Credential, l *logs.Log) error {
	return nil
}

func (a *twilioPhoneAuthImpl) restartCredentialVerification(credential *model.Credential, appName string, l *logs.Log) error {
	return nil
}

func (a *twilioPhoneAuthImpl) resetCredential(credential *model.Credential, resetCode *string, params string, l *logs.Log) (map[string]interface{}, error) {
	return nil, nil
}

func (a *twilioPhoneAuthImpl) forgotCredential(credential *model.Credential, identifier string, appName string, l *logs.Log) (map[string]interface{}, error) {
	return nil, nil
}

// initPhoneAuth initializes and registers a new phone auth instance
func initPhoneAuth(auth *Auth, twilioAccountSID string, twilioToken string, twilioServiceSID string) (*twilioPhoneAuthImpl, error) {
	phone := &twilioPhoneAuthImpl{auth: auth, authType: AuthTypeTwilioPhone, twilioAccountSID: twilioAccountSID, twilioToken: twilioToken, twilioServiceSID: twilioServiceSID}

	err := auth.registerAuthType(phone.authType, phone)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeAuthType, nil, err)
	}

	return phone, nil
}
