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

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logs"
	"github.com/rokwire/logging-library-go/v2/logutils"
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

func (a *codeVerificationImpl) checkCredentials(accountAuthType model.AccountAuthType, creds string, credential verificationCreds, l *logs.Log) (string, error) {
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

// initCodeVerification initializes and registers a new code verification instance
func initCodeVerification(auth *Auth) (*codeVerificationImpl, error) {
	code := &codeVerificationImpl{auth: auth, verificationType: VerificationTypeCode}

	err := auth.registerVerificationType(code.verificationType, code)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeVerificationType, nil, err)
	}

	return code, nil
}
