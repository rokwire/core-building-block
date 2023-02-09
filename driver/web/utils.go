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

package web

import (
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
	"encoding/json"
	"net/http"

	"github.com/rokwire/logging-library-go/v2/logs"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

// Helper for authLogin and authLoginMFA
func authBuildLoginResponse(l *logs.Log, loginSession *model.LoginSession) logs.HTTPResponse {
	//token
	accessToken := loginSession.AccessToken
	refreshToken := loginSession.CurrentRefreshToken()

	tokenType := Def.SharedResRokwireTokenTokenTypeBearer
	rokwireToken := Def.SharedResRokwireToken{AccessToken: &accessToken, RefreshToken: &refreshToken, TokenType: &tokenType}

	//account
	var accountData *Def.Account
	if loginSession.AccountAuthType != nil {
		account := loginSession.AccountAuthType.Account
		accountData = accountToDef(account)
	}

	//params
	var paramsRes Def.SharedResLogin_Params
	if loginSession.Params != nil {
		paramsBytes, err := json.Marshal(loginSession.Params)
		if err != nil {
			return l.HTTPResponseErrorAction(logutils.ActionMarshal, logutils.MessageDataType("auth login response params"), nil, err, http.StatusInternalServerError, false)
		}

		err = json.Unmarshal(paramsBytes, &paramsRes)
		if err != nil {
			return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("auth login response params"), nil, err, http.StatusInternalServerError, false)
		}
	}

	responseData := &Def.SharedResLogin{Token: &rokwireToken, Account: accountData, Params: &paramsRes}
	respData, err := json.Marshal(responseData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, logutils.MessageDataType("auth login response"), nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(respData)
}
