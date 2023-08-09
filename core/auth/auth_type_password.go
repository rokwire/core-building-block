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

func (c *passwordCreds) getCredential(key string) string {
	if key == credentialKeyPassword {
		return c.Password
	}
	return ""
}

func (c *passwordCreds) setCredential(value string, key string) {
	if key == credentialKeyPassword {
		c.Password = value
	}
}

func (c *passwordCreds) getResetParams() (*string, *time.Time) {
	return c.ResetCode, c.ResetExpiry
}

func (c *passwordCreds) setResetParams(code *string, expiry *time.Time) {
	c.ResetCode = code
	c.ResetExpiry = expiry
}

func (c *passwordCreds) toMap() (map[string]interface{}, error) {
	credBytes, err := json.Marshal(c)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typePasswordCreds, nil, err)
	}
	var credsMap map[string]interface{}
	err = json.Unmarshal(credBytes, &credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, "password creds map", nil, err)
	}
	return credsMap, nil
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

func (a *passwordAuthImpl) signUp(identifierImpl identifierType, appOrg model.ApplicationOrganization, creds string, params string, config map[string]interface{}) (string, *model.AccountIdentifier, *model.Credential, error) {
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

	message, accountIdentifier, credential, err := a.buildCredential(identifierImpl, appOrg.Application.Name, credentials.Password)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction("building", "password credentials", nil, err)
	}

	return message, accountIdentifier, credential, nil
}

func (a *passwordAuthImpl) signUpAdmin(identifierImpl identifierType, appOrg model.ApplicationOrganization, creds string) (map[string]interface{}, *model.AccountIdentifier, *model.Credential, error) {
	credentials, err := a.parseCreds(creds, false)
	if err != nil {
		return nil, nil, nil, errors.WrapErrorAction(logutils.ActionParse, typePasswordCreds, nil, err)
	}

	if credentials.Password == "" {
		credentials.Password = utils.GenerateRandomPassword(12)
	}

	_, accountIdentifier, credential, err := a.buildCredential(identifierImpl, appOrg.Application.Name, credentials.Password)
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
	resetCode, err := utils.GenerateRandomString(64)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGenerate, "reset code", nil, err)

	}
	hashedResetCode, err := bcrypt.GenerateFromPassword([]byte(resetCode), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGenerate, "reset code hash", nil, err)
	}

	hashedResetCodeStr := string(hashedResetCode)
	resetExpiry := time.Now().Add(time.Hour * 24)
	passwordCreds.setResetParams(&hashedResetCodeStr, &resetExpiry)
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
		storedResetCode, storedResetExpiry := passwordCreds.getResetParams()
		if storedResetExpiry == nil || storedResetExpiry.Before(time.Now()) {
			return nil, errors.ErrorData("expired", "reset expiration time", nil)
		}
		if storedResetCode == nil {
			return nil, errors.ErrorData(logutils.StatusMissing, "stored reset code", nil)
		}
		err = bcrypt.CompareHashAndPassword([]byte(*storedResetCode), []byte(*resetCode))
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionValidate, "password reset code", nil, err)
		}

		//Update reset data
		passwordCreds.setResetParams(nil, nil)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(resetData.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGenerate, "password hash", nil, err)
	}

	//Update password
	passwordCreds.setCredential(string(hashedPassword), credentialKeyPassword)
	credsMap, err := passwordCreds.toMap()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, "map from password creds", nil, err)
	}

	return credsMap, nil
}

func (a *passwordAuthImpl) checkCredentials(identifierImpl identifierType, accountIdentifier *model.AccountIdentifier, credentials []model.Credential, creds string, displayName string, appOrg model.ApplicationOrganization, config map[string]interface{}) (string, string, error) {
	if len(credentials) != 1 {
		return "", "", errors.ErrorData(logutils.StatusInvalid, "credential list", &logutils.FieldArgs{"count": len(credentials)})
	}

	storedCreds, err := a.mapToCreds(credentials[0].Value)
	if err != nil {
		return "", "", errors.WrapErrorAction(logutils.ActionCast, "map to password creds", nil, err)
	}
	storedCred := storedCreds.getCredential(credentialKeyPassword)

	incomingCreds, err := a.parseCreds(creds, true)
	if err != nil {
		return "", "", errors.WrapErrorAction(logutils.ActionParse, typePasswordCreds, nil, err)
	}
	incomingCred := incomingCreds.getCredential(credentialKeyPassword)

	//compare stored and request passwords
	err = bcrypt.CompareHashAndPassword([]byte(storedCred), []byte(incomingCred))
	if err != nil {
		return "", "", errors.WrapErrorAction(logutils.ActionValidate, model.TypeCredential, nil, err).SetStatus(utils.ErrorStatusInvalid)
	}

	return "", credentials[0].ID, nil
}

// Helpers

func (a *passwordAuthImpl) buildCredential(identifierImpl identifierType, appName string, password string) (string, *model.AccountIdentifier, *model.Credential, error) {
	//password hash
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionGenerate, "password hash", nil, err)
	}

	identifier, err := identifierImpl.getUserIdentifier("")
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionGet, "identifier", logutils.StringArgs(identifierImpl.getCode()), err)
	}

	message := ""
	credValue := &passwordCreds{Password: string(hashedPassword)}
	accountIdentifier := model.AccountIdentifier{ID: uuid.NewString(), Code: identifierImpl.getCode(), Identifier: identifier,
		Account: model.Account{ID: uuid.NewString()}, DateCreated: time.Now().UTC()}
	sent := false
	if identifierChannel, ok := identifierImpl.(authCommunicationChannel); ok {
		sent, err = identifierChannel.sendVerifyIdentifier(&accountIdentifier, appName)
		if err != nil {
			return "", nil, nil, errors.WrapErrorAction(logutils.ActionSend, "identifier verification", nil, err)
		}
	}
	accountIdentifier.Verified = !sent
	if sent {
		message = "verification code sent successfully"
	}

	credValueMap, err := credValue.toMap()
	if err != nil {
		return "", nil, nil, errors.WrapErrorAction(logutils.ActionCast, "map from creds", nil, err)
	}

	now := time.Now()
	credential := &model.Credential{ID: uuid.NewString(), Value: credValueMap, AuthType: model.AuthType{Code: a.authType}, DateCreated: now}

	return message, &accountIdentifier, credential, nil
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
	credBytes, err := json.Marshal(credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, "password creds map", nil, err)
	}
	var creds passwordCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typePasswordCreds, nil, err)
	}

	err = validator.New().Struct(creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionValidate, typePasswordCreds, nil, err)
	}
	return &creds, nil
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