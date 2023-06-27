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
	"encoding/json"

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

const (
	//IdentifierTypeTwilioPhone phone identifier type
	IdentifierTypeTwilioPhone string = "twilio_phone"

	servicesPathPart         string                   = "https://verify.twilio.com/v2/Services"
	verificationsPathPart    string                   = "Verifications"
	verificationCheckPart    string                   = "VerificationCheck"
	typeVerifyServiceID      logutils.MessageDataType = "phone verification service id"
	typeVerifyServiceToken   logutils.MessageDataType = "phone verification service token"
	typeVerificationResponse logutils.MessageDataType = "phone verification response"
	typeVerificationStatus   logutils.MessageDataType = "phone verification staus"
	typeVerificationSID      logutils.MessageDataType = "phone verification sid"
	typePhoneCreds           logutils.MessageDataType = "phone creds"
	typePhoneNumber          logutils.MessageDataType = "E.164 phone number"
)

// Phone implementation of identifierType
type twilioPhoneIdentifierImpl struct {
	identifierType   string
	twilioAccountSID string
	twilioToken      string
	twilioServiceSID string
}

type twilioPhoneCreds struct {
	Phone string `json:"phone" validate:"required"`
	Code  string `json:"code"`
	// TODO: Password?
}

func (c *twilioPhoneCreds) identifier() string {
	return c.Phone
}

func (c *twilioPhoneCreds) credential() string {
	return c.Code
}

func (a *twilioPhoneIdentifierImpl) getUserIdentifier(creds string) (string, error) {
	var requestCreds twilioPhoneCreds
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, typePhoneCreds, nil, err)
	}

	return requestCreds.Phone, nil
}

// initPhoneIdentifier initializes and registers a new phone identifier instance
func initPhoneIdentifier(auth *Auth, twilioAccountSID string, twilioToken string, twilioServiceSID string) (*twilioPhoneIdentifierImpl, error) {
	phone := &twilioPhoneIdentifierImpl{identifierType: IdentifierTypeTwilioPhone, twilioAccountSID: twilioAccountSID, twilioToken: twilioToken, twilioServiceSID: twilioServiceSID}

	err := auth.registerIdentifierType(phone.identifierType, phone)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeIdentifierType, nil, err)
	}

	return phone, nil
}
