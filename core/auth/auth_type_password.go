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
	"time"

	"github.com/google/uuid"
	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/go-playground/validator.v9"
)

const (
	//AuthTypePassword password auth type
	AuthTypePassword string = "password"

	credentialKeyPassword string = "password"
	typePasswordResetCode string = "password reset code"

	typePasswordCreds       logutils.MessageDataType = "password creds"
	typePasswordParams      logutils.MessageDataType = "password params"
	typePasswordResetParams logutils.MessageDataType = "password reset params"
)

// passwordCreds represents the creds struct for password authentication
type passwordCreds struct {
	Password string `json:"password" validate:"required"`

	ResetCode   *string    `json:"reset_code,omitempty"`
	ResetExpiry *time.Time `json:"reset_expiry,omitempty"`
}

func (c *passwordCreds) toMap() (map[string]interface{}, error) {
	if c == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, typePasswordCreds, nil)
	}

	credsMap, err := utils.JSONConvert[map[string]interface{}, passwordCreds](*c)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionParse, typePasswordCreds, nil, err)
	}
	if credsMap == nil {
		return nil, errors.ErrorData(logutils.StatusInvalid, "password creds map", nil)
	}
	return *credsMap, nil
}

type passwordParams struct {
	ConfirmPassword string `json:"confirm_password" validate:"required"`
}

type passwordResetParams struct {
	NewPassword string `json:"new_password" validate:"required"`
	passwordParams
}

// Password implementation of authType
type passwordAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *passwordAuthImpl) signUp(identifierImpl identifierType, accountID *string, appOrg model.ApplicationOrganization, creds string, params string) (string, *model.AccountIdentifier, *model.Credential, error) {
	credentials, err := a.parseCreds(creds, true)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionParse, typePasswordCreds, nil, err)
	}

	parameters, err := a.parseParams(params)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePasswordParams, nil, err)
	}

	if credentials.Password != parameters.ConfirmPassword {
		return "", nil, nil, errors.ErrorData(logutils.StatusInvalid, "mismatching credentials", nil)
	}

	message := ""
	var accountIdentifier *model.AccountIdentifier
	if accountID == nil {
		// we are not linking a password credential, so use the accountID generated for the identifier
		message, accountIdentifier, err = identifierImpl.buildIdentifier(nil, appOrg, a.requireIdentifierVerificationForSignIn())
		if err != nil {
			return "", nil, nil, errors.WrapErrorAction("building", "identifier", logutils.StringArgs(identifierImpl.getCode()), err)
		}
	}

	credential, err := a.buildCredential(credentials.Password)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction("building", "password credentials", nil, err)
	}

	return message, accountIdentifier, credential, nil
}

func (a *passwordAuthImpl) signUpAdmin(identifierImpl identifierType, appOrg model.ApplicationOrganization, creds string) (map[string]interface{}, *model.AccountIdentifier, *model.Credential, error) {
	credentials := &passwordCreds{}
	var err error
	if creds != "" {
		credentials, err = a.parseCreds(creds, false)
		if err != nil {
			return nil, nil, nil, errors.WrapErrorAction(logutils.ActionParse, typePasswordCreds, nil, err)
		}
	}

	if credentials.Password == "" {
		credentials.Password = utils.GenerateRandomPassword(12)
	}

	_, accountIdentifier, err := identifierImpl.buildIdentifier(nil, appOrg, a.requireIdentifierVerificationForSignIn())
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction("building", "identifier", logutils.StringArgs(identifierImpl.getCode()), err)
	}

	credential, err := a.buildCredential(credentials.Password)
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction("building", "password credentials", nil, err)
	}

	params := map[string]interface{}{"password": credentials.Password}
	return params, accountIdentifier, credential, nil
}

func (a *passwordAuthImpl) forgotCredential(identifierImpl identifierType, credential *model.Credential, appOrg model.ApplicationOrganization) (map[string]interface{}, error) {
	identifierChannel, _ := identifierImpl.(authCommunicationChannel)
	if identifierChannel == nil {
		return nil, errors.ErrorData(logutils.StatusInvalid, typeIdentifierType, logutils.StringArgs(identifierImpl.getCode()))
	}
	if credential == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeCredential, nil)
	}

	passwordCreds, err := a.mapToCreds(credential.Value)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, "map to password creds", nil, err)
	}

	//TODO: turn length of reset code into a setting
	resetCode := utils.GenerateRandomString(64)
	hashedResetCode, err := bcrypt.GenerateFromPassword([]byte(resetCode), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGenerate, "reset code hash", nil, err)
	}

	hashedResetCodeStr := string(hashedResetCode)
	resetExpiry := time.Now().UTC().Add(time.Hour * 24)
	passwordCreds.ResetCode = &hashedResetCodeStr
	passwordCreds.ResetExpiry = &resetExpiry

	_, err = identifierChannel.sendCode(appOrg.Application.Name, resetCode, typePasswordResetCode, credential.ID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionSend, "password reset code", nil, err)
	}

	credsMap, err := passwordCreds.toMap()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, "map from creds", nil, err)
	}
	return credsMap, nil
}

func (a *passwordAuthImpl) resetCredential(credential *model.Credential, resetCode *string, params string) (map[string]interface{}, error) {
	if credential == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeCredential, nil)
	}
	passwordCreds, err := a.mapToCreds(credential.Value)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, "map to password creds", nil, err)
	}

	var resetData passwordResetParams
	err = json.Unmarshal([]byte(params), &resetData)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePasswordResetParams, nil, err)
	}

	if len(resetData.NewPassword) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, logutils.TypeString, logutils.StringArgs("new password"))
	}
	if len(resetData.ConfirmPassword) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, logutils.TypeString, logutils.StringArgs("confirm password"))
	}
	//check if the password matches with the confirm password one
	if resetData.NewPassword != resetData.ConfirmPassword {
		return nil, errors.ErrorData(logutils.StatusInvalid, "mismatching password reset fields", nil)
	}

	//reset password from link
	if resetCode != nil {
		if passwordCreds.ResetExpiry == nil || passwordCreds.ResetExpiry.Before(time.Now()) {
			return nil, errors.ErrorData("expired", "reset expiration time", nil)
		}
		if passwordCreds.ResetCode == nil {
			return nil, errors.ErrorData(logutils.StatusMissing, "stored reset code", nil)
		}
		err = bcrypt.CompareHashAndPassword([]byte(*passwordCreds.ResetCode), []byte(*resetCode))
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionValidate, "password reset code", nil, err)
		}

		//Update reset data
		passwordCreds.ResetCode = nil
		passwordCreds.ResetExpiry = nil
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(resetData.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGenerate, "password hash", nil, err)
	}

	//Update password
	passwordCreds.Password = string(hashedPassword)
	credsMap, err := passwordCreds.toMap()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, "map from password creds", nil, err)
	}

	return credsMap, nil
}

func (a *passwordAuthImpl) checkCredentials(identifierImpl identifierType, accountID *string, aats []model.AccountAuthType, creds string, params string, appOrg model.ApplicationOrganization) (string, string, error) {
	if len(aats) != 1 {
		return "", "", errors.ErrorData(logutils.StatusInvalid, "account auth type list", &logutils.FieldArgs{"count": len(aats)})
	}
	if aats[0].Credential == nil {
		return "", "", errors.ErrorData(logutils.StatusInvalid, model.TypeAccountAuthType, &logutils.FieldArgs{"id": aats[0].ID, "credential": nil})
	}

	storedCreds, err := a.mapToCreds(aats[0].Credential.Value)
	if err != nil {
		return "", "", errors.WrapErrorAction(logutils.ActionCast, "map to password creds", nil, err)
	}

	incomingCreds, err := a.parseCreds(creds, true)
	if err != nil {
		return "", "", errors.WrapErrorAction(logutils.ActionParse, typePasswordCreds, nil, err)
	}

	//compare stored and request passwords
	err = bcrypt.CompareHashAndPassword([]byte(storedCreds.Password), []byte(incomingCreds.Password))
	if err != nil {
		return "", "", errors.WrapErrorAction(logutils.ActionValidate, model.TypeCredential, nil, err).SetStatus(utils.ErrorStatusInvalid)
	}

	return "", aats[0].Credential.ID, nil
}

func (a *passwordAuthImpl) withParams(params map[string]interface{}) (authType, error) {
	return a, nil
}

func (a *passwordAuthImpl) requireIdentifierVerificationForSignIn() bool {
	return true
}

func (a *passwordAuthImpl) allowMultiple() bool {
	return false
}

// Helpers

func (a *passwordAuthImpl) buildCredential(password string) (*model.Credential, error) {
	//password hash
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGenerate, "password hash", nil, err)
	}

	credValue := &passwordCreds{Password: string(hashedPassword)}
	credValueMap, err := credValue.toMap()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, "map from creds", nil, err)
	}

	credential := &model.Credential{ID: uuid.NewString(), Value: credValueMap, AuthType: model.AuthType{Code: a.authType}, DateCreated: time.Now().UTC()}
	return credential, nil
}

func (a *passwordAuthImpl) parseCreds(creds string, validate bool) (*passwordCreds, error) {
	var credential passwordCreds
	err := json.Unmarshal([]byte(creds), &credential)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePasswordCreds, nil, err)
	}

	if validate {
		err = validator.New().Struct(credential)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionValidate, typePasswordCreds, nil, err)
		}
	}
	return &credential, nil
}

func (a *passwordAuthImpl) parseParams(params string) (*passwordParams, error) {
	var parameters passwordParams
	err := json.Unmarshal([]byte(params), &parameters)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePasswordParams, nil, err)
	}
	err = validator.New().Struct(parameters)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, typePasswordParams, nil, err)
	}
	return &parameters, nil
}

func (a *passwordAuthImpl) mapToCreds(credsMap map[string]interface{}) (*passwordCreds, error) {
	creds, err := utils.JSONConvert[passwordCreds, map[string]interface{}](credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionParse, typePasswordCreds, nil, err)
	}

	err = validator.New().Struct(creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, typePasswordCreds, nil, err)
	}
	return creds, nil
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
