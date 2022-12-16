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
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
)

const (
	//MfaTypePhone phone mfa type
	MfaTypePhone string = "phone"
)

// Phone implementation of mfaType
type phoneMfaImpl struct {
	auth    *Auth
	mfaType string
}

func (m *phoneMfaImpl) verify(storage interfaces.Storage, mfa *model.MFAType, accountID string, code string) (*string, error) {
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

func (m *phoneMfaImpl) enroll(identifier string) (*model.MFAType, error) {
	if identifier == "" {
		return nil, errors.ErrorData(logutils.StatusMissing, "identifier", nil)
	}

	//TODO: check identifier is valid phone number

	params := map[string]interface{}{
		"identifier": identifier,
	}

	id, _ := uuid.NewUUID()
	return &model.MFAType{ID: id.String(), Type: MfaTypePhone, Verified: false, Params: params, DateCreated: time.Now().UTC()}, nil
}

func (m *phoneMfaImpl) sendCode(identifier string) (string, *time.Time, error) {
	code := fmt.Sprintf("%06d", utils.GenerateRandomInt(mfaCodeMax))
	expires := time.Now().Add(time.Duration(mfaCodeExpiration) * time.Minute)

	//TODO: send code to identifier, store both in DB

	return code, &expires, errors.New(logutils.Unimplemented)
}

// initPhoneMfa initializes and registers a new phone mfa instance
func initPhoneMfa(auth *Auth) (*phoneMfaImpl, error) {
	phone := &phoneMfaImpl{auth: auth, mfaType: MfaTypePhone}

	err := auth.registerMfaType(phone.mfaType, phone)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeMfaType, nil, err)
	}

	return phone, nil
}
