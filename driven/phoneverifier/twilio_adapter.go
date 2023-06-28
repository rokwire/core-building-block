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

package phoneverifier

import (
	"context"
	"core-building-block/utils"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

const (
	typeTwilio logutils.MessageDataType = "twilio_phone"

	servicesPathPart                                  = "https://verify.twilio.com/v2/Services"
	verificationsPathPart                             = "Verifications"
	verificationCheckPart                             = "VerificationCheck"
	typeVerifyServiceID      logutils.MessageDataType = "phone verification service id"
	typeVerifyServiceToken   logutils.MessageDataType = "phone verification service token"
	typeVerificationResponse logutils.MessageDataType = "phone verification response"
	typeVerificationStatus   logutils.MessageDataType = "phone verification staus"
	typeVerificationSID      logutils.MessageDataType = "phone verification sid"
)

// TwilioAdapter implements the Emailer interface
type TwilioAdapter struct {
	accountSID string
	token      string
	serviceSID string
	httpClient *http.Client
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

// Identifier returns an identifying string for the adapter
func (a *TwilioAdapter) Identifier() string {
	return string(typeTwilio)
}

// StartVerification begins the phone verification process
func (a *TwilioAdapter) StartVerification(phone string, data url.Values) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	body, err := a.makeRequest(ctx, "POST", servicesPathPart+"/"+a.serviceSID+"/"+verificationsPathPart, data, a.accountSID, a.token)
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

// CheckVerification verifies the code sent to a user's phone to finish verification
func (a *TwilioAdapter) CheckVerification(phone string, data url.Values) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	body, err := a.makeRequest(ctx, "POST", servicesPathPart+"/"+a.serviceSID+"/"+verificationCheckPart, data, a.accountSID, a.token)
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

func (a *TwilioAdapter) makeRequest(ctx context.Context, method string, pathPart string, data url.Values, user string, token string) ([]byte, error) {
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
		req.Header.Add("Authorization", "Basic "+a.basicAuth(user, token))
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, errors.WrapErrorAction(logAction, logutils.TypeRequest, nil, err)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err)
	}
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return nil, errors.ErrorData(logutils.StatusInvalid, logutils.TypeResponse, &logutils.FieldArgs{"status_code": resp.StatusCode, "error": string(body)})
	}
	return body, nil
}

func (a *TwilioAdapter) basicAuth(username, password string) string {
	auth := username + ":" + password
	return base64.StdEncoding.EncodeToString([]byte(auth))
}

// NewTwilioAdapter creates a new twilio phone verifier adapter instance
func NewTwilioAdapter(accountSID string, token string, serviceSID string) (*TwilioAdapter, error) {
	if accountSID == "" {
		return nil, errors.ErrorData(logutils.StatusMissing, typeVerifyServiceID, nil)
	}
	if token == "" {
		return nil, errors.ErrorData(logutils.StatusMissing, typeVerifyServiceToken, nil)
	}

	client := &http.Client{}
	return &TwilioAdapter{accountSID: accountSID, token: token, serviceSID: serviceSID, httpClient: client}, nil
}
