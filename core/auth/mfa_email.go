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
	"core-building-block/core/interfaces"
	"core-building-block/core/model"
	"core-building-block/utils"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

const (
	//MfaTypeEmail email mfa type
	MfaTypeEmail string = "email"
)

// Email implementation of mfaType
type emailMfaImpl struct {
	auth    *Auth
	mfaType string
}

func (m *emailMfaImpl) verify(storage interfaces.Storage, mfa *model.MFAType, accountID string, code string) (*string, error) {
	if mfa == nil || mfa.Params == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, "mfa params", nil)
	}

	var message string

	storedCode, ok := mfa.Params["code"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusInvalid, "stored mfa code", nil)
	}
	if code != storedCode {
		message = "invalid code"
		return &message, errors.ErrorData(logutils.StatusInvalid, "mfa code", nil)
	}

	expiry, ok := mfa.Params["expires"].(time.Time)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusInvalid, "stored expiry", nil)
	}
	if time.Now().UTC().After(expiry) {
		message = "expired code"
		return &message, errors.ErrorData(logutils.StatusInvalid, "expired code", nil)
	}

	//remove code and expiration from params in storage
	delete(mfa.Params, "code")
	delete(mfa.Params, "expires")
	err := storage.UpdateMFAType(mfa, accountID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeMFAType, nil, err)
	}

	return nil, nil
}

func (m *emailMfaImpl) enroll(identifier string) (*model.MFAType, error) {
	if identifier == "" {
		return nil, errors.ErrorData(logutils.StatusMissing, "identifier", nil)
	}

	//TODO: check identifier is valid email address

	params := map[string]interface{}{
		"identifier": identifier,
	}

	id, _ := uuid.NewUUID()
	return &model.MFAType{ID: id.String(), Type: MfaTypeEmail, Verified: false, Params: params, DateCreated: time.Now().UTC()}, nil
}

func (m *emailMfaImpl) sendCode(identifier string) (string, *time.Time, error) {
	code := fmt.Sprintf("%06d", utils.GenerateRandomInt(mfaCodeMax))
	expires := time.Now().Add(time.Duration(mfaCodeExpiration) * time.Minute)

	//TODO: send code to identifier, store both in DB

	return code, &expires, errors.New(logutils.Unimplemented)
}

// initEmailMfa initializes and registers a new email mfa instance
func initEmailMfa(auth *Auth) (*emailMfaImpl, error) {
	email := &emailMfaImpl{auth: auth, mfaType: MfaTypeEmail}

	err := auth.registerMfaType(email.mfaType, email)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeMFAType, nil, err)
	}

	return email, nil
}
