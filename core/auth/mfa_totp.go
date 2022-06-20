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
	"bytes"
	"core-building-block/core/model"
	"core-building-block/driven/storage"
	"image/png"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
)

const (
	//MfaTypeTotp totp mfa type
	MfaTypeTotp string = "totp"
)

// TOTP implementation of mfaType
type totpMfaImpl struct {
	auth    *Auth
	mfaType string
}

func (m *totpMfaImpl) verify(context storage.TransactionContext, mfa *model.MFAType, accountID string, code string) (*string, error) {
	if mfa == nil || mfa.Params == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, "mfa params", nil)
	}

	secret, ok := mfa.Params["secret"].(string)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusInvalid, "stored totp secret", nil)
	}
	if !totp.Validate(code, secret) {
		message := "invalid code"
		return &message, errors.ErrorData(logutils.StatusInvalid, "mfa code", nil)
	}

	return nil, nil
}

func (m *totpMfaImpl) enroll(identifier string) (*model.MFAType, error) {
	totpOpts := totp.GenerateOpts{
		Issuer:      m.auth.host,
		AccountName: identifier,
	}
	key, err := totp.Generate(totpOpts)
	if err != nil {
		return nil, errors.WrapErrorAction("generate", "TOTP key", nil, err)
	}

	var buf bytes.Buffer
	image, err := key.Image(256, 256)
	if err != nil {
		return nil, errors.WrapErrorAction("generate", "TOTP image", nil, err)
	}
	err = png.Encode(&buf, image)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionEncode, "TOTP image", nil, err)
	}

	params := map[string]interface{}{
		"identifier": identifier,
		"secret":     key.Secret(),
		"qr_code":    buf.String(),
	}

	id, _ := uuid.NewUUID()
	return &model.MFAType{ID: id.String(), Type: MfaTypeTotp, Verified: false, Params: params, DateCreated: time.Now().UTC()}, nil
}

//sendCode not used for TOTP
func (m *totpMfaImpl) sendCode(identifier string) (string, *time.Time, error) {
	return "", nil, errors.New(logutils.Unimplemented)
}

//initTotpMfa initializes and registers a new totp mfa instance
func initTotpMfa(auth *Auth) (*totpMfaImpl, error) {
	totp := &totpMfaImpl{auth: auth, mfaType: MfaTypeTotp}

	err := auth.registerMfaType(totp.mfaType, totp)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeMfaType, nil, err)
	}

	return totp, nil
}
