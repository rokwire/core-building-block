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
	"core-building-block/core"
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
	"core-building-block/utils"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	"github.com/gorilla/mux"
	"github.com/rokwire/core-auth-library-go/v2/authorization"
	"github.com/rokwire/core-auth-library-go/v2/sigauth"
	"github.com/rokwire/core-auth-library-go/v2/tokenauth"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

// TPSApisHandler handles the APIs implementation used by third-party services
type TPSApisHandler struct {
	coreAPIs *core.APIs
}

func (h TPSApisHandler) getServiceRegistrations(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	serviceIDsParam := r.URL.Query().Get("ids")
	if serviceIDsParam == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("ids"), nil, http.StatusBadRequest, false)
	}
	serviceIDs := strings.Split(serviceIDsParam, ",")

	serviceRegs := h.coreAPIs.Auth.GetServiceRegistrations(serviceIDs)
	serviceRegResp := authServiceRegListToDef(serviceRegs)

	data, err := json.Marshal(serviceRegResp)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeServiceReg, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

func (h TPSApisHandler) getAuthKeys(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	keys, err := h.coreAPIs.Auth.GetAuthKeySet()
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeJSONWebKeySet, logutils.StringArgs("auth"), err, http.StatusInternalServerError, true)
	}

	keysResp := jsonWebKeySetDef(keys)

	data, err := json.Marshal(keysResp)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeJSONWebKeySet, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

func (h TPSApisHandler) getServiceAccountParams(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	params := mux.Vars(r)
	accountID := params["id"]
	if len(accountID) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	req, err := sigauth.ParseHTTPRequest(r)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionParse, "service account params http request", nil, err, http.StatusInternalServerError, false)
	}

	accountParams, err := h.coreAPIs.Auth.GetServiceAccountParams(accountID, false, req, l)
	if err != nil {
		if loggingErr, ok := err.(*errors.Error); ok {
			status := loggingErr.Status()
			if status == utils.ErrorStatusInvalid || status == utils.ErrorStatusNotFound {
				return l.HttpResponseError("Error getting service account params", err, http.StatusUnauthorized, true)
			}
		}
		return l.HttpResponseError("Error getting service account params", err, http.StatusInternalServerError, true)
	}

	appOrgPairs := appOrgPairListToDef(accountParams)

	respData, err := json.Marshal(appOrgPairs)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, logutils.MessageDataType("service account params response"), nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(respData)
}

func (h TPSApisHandler) getServiceAccessToken(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	req, err := sigauth.ParseHTTPRequest(r)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionParse, "service access token http request", nil, err, http.StatusInternalServerError, false)
	}

	accessToken, err := h.coreAPIs.Auth.GetServiceAccessToken(false, req, l)
	if err != nil {
		if loggingErr, ok := err.(*errors.Error); ok {
			status := loggingErr.Status()
			if status == utils.ErrorStatusInvalid || status == utils.ErrorStatusNotFound {
				return l.HttpResponseError("Error getting access token", err, http.StatusUnauthorized, true)
			}
		}
		return l.HttpResponseError("Error getting access token", err, http.StatusInternalServerError, true)
	}

	tokenType := Def.SharedResRokwireTokenTokenTypeBearer
	rokwireToken := Def.SharedResRokwireToken{AccessToken: &accessToken, TokenType: &tokenType}

	respData, err := json.Marshal(rokwireToken)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, logutils.MessageDataType("service access token response"), nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(respData)
}

func (h TPSApisHandler) getServiceAccessTokens(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	req, err := sigauth.ParseHTTPRequest(r)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionParse, "service access tokens http request", nil, err, http.StatusInternalServerError, false)
	}

	accessTokens, err := h.coreAPIs.Auth.GetAllServiceAccessTokens(false, req, l)
	if err != nil {
		if loggingErr, ok := err.(*errors.Error); ok {
			status := loggingErr.Status()
			if status == utils.ErrorStatusInvalid || status == utils.ErrorStatusNotFound {
				return l.HttpResponseError("Error getting access tokens", err, http.StatusUnauthorized, true)
			}
		}
		return l.HttpResponseError("Error getting access tokens", err, http.StatusInternalServerError, true)
	}

	rokwireTokens := make([]Def.ServicesResServiceAccountsAccessTokens, len(accessTokens))
	i := 0
	for appOrgPair, token := range accessTokens {
		tokenType := Def.SharedResRokwireTokenTokenTypeBearer
		accessToken := token
		rokwireToken := Def.SharedResRokwireToken{AccessToken: &accessToken, TokenType: &tokenType}

		rokwireTokens[i] = Def.ServicesResServiceAccountsAccessTokens{AppId: appOrgPair.AppID, OrgId: appOrgPair.OrgID, Token: rokwireToken}
		i++
	}

	respData, err := json.Marshal(rokwireTokens)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, logutils.MessageDataType("service access tokens response"), nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(respData)
}

func (h TPSApisHandler) getAccounts(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	if claims.Scope == "" {
		return l.HttpResponseErrorData(logutils.StatusInvalid, model.TypeScope, nil, nil, http.StatusForbidden, true)
	}

	var queryParams map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&queryParams)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	responseKeys := make([]string, 0)
	searchParams := make(map[string]interface{})
	scopeStrings := strings.Split(claims.Scope, " ")
	scopes, err := scopeListFromDef(&scopeStrings)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionParse, model.TypeScope, nil, err, http.StatusInternalServerError, true)
	}

	allAccess := false
	allAccessScope := authorization.Scope{ServiceID: "core", Resource: string(model.TypeAccount), Operation: "get"}
	for k, v := range queryParams {
		if !allAccess {
			validKey := false
			requiredScope := authorization.Scope{ServiceID: "core", Resource: fmt.Sprintf("%s.%s", string(model.TypeAccount), k), Operation: "get"}
			for _, scope := range scopes {
				if scope.Match(&requiredScope) {
					allAccess = scope.Match(&allAccessScope)
					validKey = true
					break
				}
			}
			if !validKey {
				return l.HttpResponseErrorData(logutils.StatusInvalid, "accounts search parameter", &logutils.FieldArgs{k: v}, nil, http.StatusForbidden, true)
			}
		}

		responseKeys = append(responseKeys, k)
		searchParams[k] = v
	}

	accounts, err := h.coreAPIs.TPS.TPSGetAccounts(searchParams, allAccess)
	if err != nil {
		errFields := logutils.FieldArgs(searchParams)
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeAccount, &errFields, err, http.StatusInternalServerError, false)
	}

	var accountsResp interface{}
	if allAccess {
		accountsResp = accounts
	} else {
		accountsResp := make([]map[string]interface{}, len(accounts))
		for i, account := range accounts {
			restrictedData := make(map[string]interface{})
			for _, key := range responseKeys {
				restrictedData[key] = reflect.ValueOf(account).FieldByName(key).Interface()
			}
			accountsResp[i] = restrictedData
		}
	}

	respData, err := json.Marshal(accountsResp)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, logutils.MessageDataType("accounts response"), nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(respData)
}

// NewTPSApisHandler creates new tps Handler instance
func NewTPSApisHandler(coreAPIs *core.APIs) TPSApisHandler {
	return TPSApisHandler{coreAPIs: coreAPIs}
}
