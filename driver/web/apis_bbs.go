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
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/rokwire/core-auth-library-go/v2/sigauth"
	"github.com/rokwire/core-auth-library-go/v2/tokenauth"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

// BBsApisHandler handles the APIs implementation used by the platform building blocks
type BBsApisHandler struct {
	coreAPIs *core.APIs
}

// getTest TODO get test
func (h BBsApisHandler) getTest(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	res := h.coreAPIs.BBs.BBsGetTest()

	return l.HttpResponseSuccessMessage(res)
}

func (h BBsApisHandler) getServiceRegistrations(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	serviceIDsParam := r.URL.Query().Get("ids")
	if serviceIDsParam == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("ids"), nil, http.StatusBadRequest, false)
	}
	serviceIDs := strings.Split(serviceIDsParam, ",")

	serviceRegs, err := h.coreAPIs.Auth.GetServiceRegistrations(serviceIDs)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeServiceReg, nil, err, http.StatusInternalServerError, true)
	}

	serviceRegResp := authServiceRegListToDef(serviceRegs)

	data, err := json.Marshal(serviceRegResp)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeServiceReg, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

func (h BBsApisHandler) getServiceAccountParams(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	params := mux.Vars(r)
	accountID := params["id"]
	if len(accountID) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	req, err := sigauth.ParseHTTPRequest(r)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionParse, "service account params http request", nil, err, http.StatusInternalServerError, false)
	}

	accountParams, err := h.coreAPIs.Auth.GetServiceAccountParams(accountID, true, req, l)
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

func (h BBsApisHandler) getServiceAccessToken(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	req, err := sigauth.ParseHTTPRequest(r)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionParse, "service access token http request", nil, err, http.StatusInternalServerError, false)
	}

	accessToken, err := h.coreAPIs.Auth.GetServiceAccessToken(true, req, l)
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

func (h BBsApisHandler) getServiceAccessTokens(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	req, err := sigauth.ParseHTTPRequest(r)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionParse, "service access tokens http request", nil, err, http.StatusInternalServerError, false)
	}

	accessTokens, err := h.coreAPIs.Auth.GetAllServiceAccessTokens(true, req, l)
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

func (h BBsApisHandler) updatePermissions(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorData(logutils.StatusInvalid, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData []Def.Permission
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeAPIKey, nil, err, http.StatusBadRequest, true)
	}

	permissions := applicationPermissionsFromDef(requestData)
	permissions, err = h.coreAPIs.BBs.BBsUpdatePermissions(permissions, claims.Subject)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypePermission, nil, err, http.StatusInternalServerError, true)
	}

	respData, err := json.Marshal(permissions)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, logutils.MessageDataType("service access tokens response"), nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(respData)
}

// NewBBsApisHandler creates new bbs Handler instance
func NewBBsApisHandler(coreAPIs *core.APIs) BBsApisHandler {
	return BBsApisHandler{coreAPIs: coreAPIs}
}
