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
	"core-building-block/core/model"
	"core-building-block/utils"
	"encoding/json"

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logs"
	"github.com/rokwire/logging-library-go/v2/logutils"
	"golang.org/x/crypto/bcrypt"
)

const (
	authTypeUsername   string                   = "username"
	typeUsernameCreds  logutils.MessageDataType = "username creds"
	typeUsernameParams logutils.MessageDataType = "username params"
)

// Username implementation of authType
type usernameAuthImpl struct {
	auth     *Auth
	authType string
}

// userNameCreds represents the creds struct for username auth
type usernameCreds struct {
	Username string `json:"username" bson:"username" validate:"required"`
	Password string `json:"password" bson:"password"`
}

func (a *usernameAuthImpl) signUp(supportedAuthType model.SupportedAuthType, appOrg model.ApplicationOrganization, creds string, params string, newCredentialID string, l *logs.Log) (string, map[string]interface{}, error) {
	type signUpUsernameParams struct {
		ConfirmPassword string `json:"confirm_password"`
	}

	var sUsernameCreds usernameCreds
	err := json.Unmarshal([]byte(creds), &sUsernameCreds)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeUsernameCreds, nil, err)
	}

	var sUsernameParams signUpUsernameParams
	err = json.Unmarshal([]byte(params), &sUsernameParams)
	if err != nil {
		return "", nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeUsernameParams, nil, err)
	}

	username := sUsernameCreds.Username
	password := sUsernameCreds.Password
	confirmPassword := sUsernameParams.ConfirmPassword
	if len(username) == 0 {
		return "", nil, errors.ErrorData(logutils.StatusMissing, typeUsernameCreds, logutils.StringArgs("username"))
	}
	if len(password) == 0 {
		return "", nil, errors.ErrorData(logutils.StatusMissing, typeUsernameCreds, logutils.StringArgs("password"))
	}

	if len(confirmPassword) == 0 {
		return "", nil, errors.ErrorData(logutils.StatusMissing, typeUsernameParams, logutils.StringArgs("confirm_password"))
	}
	//check if the password matches with the confirm password one
	if password != confirmPassword {
		return "", nil, errors.ErrorData(logutils.StatusInvalid, "mismatching password fields", nil)
	}

	usernameCreds, err := a.buildCredentials(supportedAuthType.AuthType, appOrg.Application.Name, username, password, newCredentialID)
	if err != nil {
		return "", nil, errors.WrapErrorAction("building", "username credentials", nil, err)
	}

	return "", usernameCreds, nil
}

func (a *usernameAuthImpl) signUpAdmin(authType model.AuthType, appOrg model.ApplicationOrganization, identifier string, password string, newCredentialID string) (map[string]interface{}, map[string]interface{}, error) {
	if password == "" {
		password = utils.GenerateRandomPassword(12)
	}

	usernameCreds, err := a.buildCredentials(authType, appOrg.Application.Name, identifier, password, newCredentialID)
	if err != nil {
		return nil, nil, errors.WrapErrorAction("building", "username credentials", nil, err)
	}

	params := map[string]interface{}{"password": password}
	return params, usernameCreds, nil
}

func (a *usernameAuthImpl) buildCredentials(authType model.AuthType, appName string, username string, password string, credID string) (map[string]interface{}, error) {

	//password hash
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGenerate, "password hash", nil, err)
	}

	usernameCredValue := usernameCreds{Username: username, Password: string(hashedPassword)}

	usernameCredValueMap, err := usernameCredsToMap(&usernameCredValue)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, "map from username creds", nil, err)
	}

	return usernameCredValueMap, nil
}

func usernameCredsToMap(creds *usernameCreds) (map[string]interface{}, error) {
	credBytes, err := json.Marshal(creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typeUsernameCreds, nil, err)
	}
	var credsMap map[string]interface{}
	err = json.Unmarshal(credBytes, &credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, "map from username creds", nil, err)
	}
	return credsMap, nil
}

func (a *usernameAuthImpl) getUserIdentifier(creds string) (string, error) {
	var requestCreds usernameCreds
	err := json.Unmarshal([]byte(creds), &requestCreds)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, typeUsernameCreds, nil, err)
	}

	return requestCreds.Username, nil
}

func (a *usernameAuthImpl) verifyCredential(credential *model.Credential, verification string, l *logs.Log) (map[string]interface{}, error) {
	return nil, errors.New(logutils.Unimplemented)
}

func (a *usernameAuthImpl) sendVerifyCredential(credential *model.Credential, appName string, l *logs.Log) error {
	return nil
}

func (a *usernameAuthImpl) restartCredentialVerification(credential *model.Credential, appName string, l *logs.Log) error {
	return nil
}

func (a *usernameAuthImpl) isCredentialVerified(credential *model.Credential, l *logs.Log) (*bool, *bool, error) {
	//TODO verification process for usernames
	verified := true
	expired := false
	return &verified, &expired, nil
}

func (a *usernameAuthImpl) checkCredentials(accountAuthType model.AccountAuthType, creds string, l *logs.Log) (string, error) {
	//get stored credential
	storedCreds, err := mapToUsernameCreds(accountAuthType.Credential.Value)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionCast, typeUsernameCreds, nil, err)
	}

	//get request credential
	type signInPasswordCred struct {
		Password string `json:"password"`
	}
	var sPasswordParams signInPasswordCred
	err = json.Unmarshal([]byte(creds), &sPasswordParams)
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionUnmarshal, "sign in password creds", nil, err)
	}
	requestPassword := sPasswordParams.Password

	//compare stored and requests ones
	err = bcrypt.CompareHashAndPassword([]byte(storedCreds.Password), []byte(requestPassword))
	if err != nil {
		return "", errors.WrapErrorAction(logutils.ActionValidate, model.TypeCredential, nil, err).SetStatus(utils.ErrorStatusInvalid)
	}

	return "", nil
}

func mapToUsernameCreds(credsMap map[string]interface{}) (*usernameCreds, error) {
	credBytes, err := json.Marshal(credsMap)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typeUsernameCreds, nil, err)
	}
	var creds usernameCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeUsernameCreds, nil, err)
	}
	return &creds, nil
}

func (a *usernameAuthImpl) resetCredential(credential *model.Credential, resetCode *string, params string, l *logs.Log) (map[string]interface{}, error) {
	//get the data from params
	type Params struct {
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
	}

	var paramsData Params
	err := json.Unmarshal([]byte(params), &paramsData)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeUsernameParams, nil, err)
	}
	newPassword := paramsData.NewPassword
	confirmPassword := paramsData.ConfirmPassword

	if len(newPassword) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, logutils.TypeString, logutils.StringArgs("new_password"))
	}
	if len(confirmPassword) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, logutils.TypeString, logutils.StringArgs("confirm_password"))
	}
	//check if the password matches with the confirm password one
	if newPassword != confirmPassword {
		return nil, errors.ErrorData(logutils.StatusInvalid, "mismatching password fields", nil)
	}

	credBytes, err := json.Marshal(credential.Value)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionMarshal, typeUsernameCreds, nil, err)
	}

	var creds *usernameCreds
	err = json.Unmarshal(credBytes, &creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, typeUsernameCreds, nil, err)
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGenerate, "password hash", nil, err)
	}

	//Update verification data
	creds.Password = string(hashedPassword)
	credsMap, err := usernameCredsToMap(creds)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCast, "map from username creds", nil, err)
	}

	return credsMap, nil
}

func (a *usernameAuthImpl) forgotCredential(credential *model.Credential, identifier string, appName string, l *logs.Log) (map[string]interface{}, error) {
	return nil, nil
}

// initUsernameAuth initializes and registers a new username auth instance
func initUsernameAuth(auth *Auth) (*usernameAuthImpl, error) {
	username := &usernameAuthImpl{auth: auth, authType: authTypeUsername}

	err := auth.registerAuthType(username.authType, username)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, model.TypeAuthType, nil, err)
	}

	return username, nil
}
