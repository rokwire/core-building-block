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
	"github.com/rokwire/core-auth-library-go/v2/tokenauth"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

// SystemApisHandler handles system APIs implementation
type SystemApisHandler struct {
	coreAPIs *core.APIs
}

// createGlobalConfig creates a global config
func (h SystemApisHandler) createGlobalConfig(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.GlobalConfig
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeGlobalConfig, nil, err, http.StatusBadRequest, true)
	}

	_, err = h.coreAPIs.System.SysCreateGlobalConfig(requestData.Setting)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionCreate, model.TypeGlobalConfig, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

// getGlobalConfig gets config
func (h SystemApisHandler) getGlobalConfig(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	config, err := h.coreAPIs.System.SysGetGlobalConfig()
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeGlobalConfig, nil, err, http.StatusInternalServerError, true)
	}

	var responseData *Def.GlobalConfig
	if config != nil {
		responseData = &Def.GlobalConfig{Setting: config.Setting}
	}
	data, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeGlobalConfig, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

// updateGlobalConfig updates global config
func (h SystemApisHandler) updateGlobalConfig(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var updateConfig Def.GlobalConfig
	err = json.Unmarshal(data, &updateConfig)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeGlobalConfig, nil, err, http.StatusBadRequest, true)
	}

	setting := updateConfig.Setting

	err = h.coreAPIs.System.SysUpdateGlobalConfig(setting)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypeGlobalConfig, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

// createOrganization creates organization
func (h SystemApisHandler) createOrganization(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.SystemReqCreateOrganization
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeOrganization, nil, err, http.StatusBadRequest, true)
	}

	name := requestData.Name
	types := requestData.Type
	domains := requestData.Config.Domains

	_, err = h.coreAPIs.System.SysCreateOrganization(name, string(types), *domains)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionCreate, model.TypeOrganization, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

// updateOrganization updates organization
func (h SystemApisHandler) updateOrganization(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorData(logutils.StatusInvalid, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}
	var requestData Def.SystemReqUpdateOrganization
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeOrganization, nil, err, http.StatusBadRequest, true)
	}

	name := requestData.Name
	requestType := requestData.Type
	organizationDomains := requestData.Config.Domains

	err = h.coreAPIs.System.SysUpdateOrganization(ID, name, string(requestType), *organizationDomains)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypeOrganization, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

// getOrganization gets organization
func (h SystemApisHandler) getOrganization(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}
	org, err := h.coreAPIs.System.SysGetOrganization(ID)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeOrganization, nil, err, http.StatusInternalServerError, true)
	}
	if org == nil {
		return l.HttpResponseErrorData(logutils.StatusMissing, model.TypeOrganization, &logutils.FieldArgs{"id": ID}, nil, http.StatusNotFound, false)
	}

	responseData := organizationToDef(org)
	data, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeOrganization, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

// getOrganizations gets organizations
func (h SystemApisHandler) getOrganizations(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	organizations, err := h.coreAPIs.System.SysGetOrganizations()
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeOrganization, nil, err, http.StatusInternalServerError, true)
	}

	response := organizationsToDef(organizations)

	data, err := json.Marshal(response)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeOrganization, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

func (h SystemApisHandler) getServiceRegistrations(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	serviceIDsParam := r.URL.Query().Get("ids")
	if serviceIDsParam == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("ids"), nil, http.StatusBadRequest, false)
	}
	serviceIDs := strings.Split(serviceIDsParam, ",")

	serviceRegs := h.coreAPIs.Auth.GetServiceRegistrations(serviceIDs)
	serviceRegResp := serviceRegListToDef(serviceRegs)

	data, err := json.Marshal(serviceRegResp)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeServiceReg, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

func (h SystemApisHandler) registerService(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ServiceReg
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeServiceReg, nil, err, http.StatusBadRequest, true)
	}

	serviceReg, err := serviceRegFromDef(&requestData)
	if err != nil {
		return l.HttpResponseErrorData(logutils.StatusInvalid, model.TypeServiceReg, nil, err, http.StatusBadRequest, true)
	}

	err = h.coreAPIs.Auth.RegisterService(serviceReg)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionCreate, model.TypeServiceReg, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h SystemApisHandler) updateServiceRegistration(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorData(logutils.StatusInvalid, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ServiceReg
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeServiceReg, nil, err, http.StatusBadRequest, true)
	}

	serviceReg, err := serviceRegFromDef(&requestData)
	if err != nil {
		return l.HttpResponseErrorData(logutils.StatusInvalid, model.TypeServiceReg, nil, err, http.StatusBadRequest, true)
	}

	err = h.coreAPIs.Auth.UpdateServiceRegistration(serviceReg)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypeServiceReg, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h SystemApisHandler) deregisterService(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	serviceID := r.URL.Query().Get("id")
	if serviceID == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	err := h.coreAPIs.Auth.DeregisterService(serviceID)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionDelete, model.TypeServiceReg, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h SystemApisHandler) getServiceAccounts(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	searchParams := make(map[string]interface{})
	query := r.URL.Query()
	if query.Get("account_id") != "" {
		searchParams["account_id"] = query.Get("account_id")
	}
	if query.Get("name") != "" {
		searchParams["name"] = query.Get("name")
	}
	if query.Get("app_id") != "" {
		searchParams["app_id"] = query.Get("app_id")
	}
	if query.Get("org_id") != "" {
		searchParams["org_id"] = query.Get("org_id")
	}
	if query.Get("permissions") != "" {
		searchParams["permissions"] = strings.Split(query.Get("permissions"), ",")
	}

	serviceAccounts, err := h.coreAPIs.Auth.GetServiceAccounts(searchParams)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeServiceAccount, nil, err, http.StatusInternalServerError, true)
	}

	serviceAccountsResp := serviceAccountListToDef(serviceAccounts)

	data, err := json.Marshal(serviceAccountsResp)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeServiceAccount, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

func (h SystemApisHandler) registerServiceAccount(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	fromAppID := utils.StringOrNil(r.URL.Query().Get("app_id"))
	fromOrgID := utils.StringOrNil(r.URL.Query().Get("org_id"))

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorData(logutils.StatusInvalid, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.SystemReqCreateServiceAccount
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeServiceAccount, nil, err, http.StatusBadRequest, true)
	}

	var creds []model.ServiceAccountCredential
	if requestData.Creds != nil {
		creds = serviceAccountCredentialListFromDef(*requestData.Creds)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	serviceAccount, err := h.coreAPIs.Auth.RegisterServiceAccount(requestData.AccountId, fromAppID, fromOrgID, requestData.Name,
		requestData.AppId, requestData.OrgId, requestData.Permissions, requestData.FirstParty, creds, assignerPermissions, l)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRegister, model.TypeServiceAccount, nil, err, http.StatusInternalServerError, true)
	}

	serviceAccountResp := serviceAccountToDef(serviceAccount)

	data, err = json.Marshal(serviceAccountResp)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeServiceAccount, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

func (h SystemApisHandler) deregisterServiceAccount(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	accountID := r.URL.Query().Get("account_id")
	if accountID == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("account_id"), nil, http.StatusBadRequest, false)
	}

	err := h.coreAPIs.Auth.DeregisterServiceAccount(accountID)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionDeregister, model.TypeServiceAccount, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h SystemApisHandler) getServiceAccountInstance(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	params := mux.Vars(r)
	id := params["id"]
	if len(id) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	appID := r.URL.Query().Get("app_id")
	if len(id) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("app_id"), nil, http.StatusBadRequest, false)
	}
	orgID := r.URL.Query().Get("org_id")
	if len(id) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("org_id"), nil, http.StatusBadRequest, false)
	}

	serviceAccount, err := h.coreAPIs.Auth.GetServiceAccountInstance(id, appID, orgID)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeServiceAccount, nil, err, http.StatusInternalServerError, true)
	}

	serviceAccountResp := serviceAccountToDef(serviceAccount)

	data, err := json.Marshal(serviceAccountResp)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeServiceAccount, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

func (h SystemApisHandler) updateServiceAccountInstance(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	params := mux.Vars(r)
	id := params["id"]
	if len(id) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	appID := r.URL.Query().Get("app_id")
	if len(id) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("app_id"), nil, http.StatusBadRequest, false)
	}
	orgID := r.URL.Query().Get("org_id")
	if len(id) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("org_id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorData(logutils.StatusInvalid, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.SystemReqUpdateServiceAccount
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, "service account update request", nil, err, http.StatusBadRequest, true)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	serviceAccount, err := h.coreAPIs.Auth.UpdateServiceAccountInstance(id, appID, orgID, requestData.Name, requestData.Permissions, assignerPermissions)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypeServiceAccount, nil, err, http.StatusInternalServerError, true)
	}

	serviceAccountResp := serviceAccountToDef(serviceAccount)

	data, err = json.Marshal(serviceAccountResp)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeServiceAccount, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

func (h SystemApisHandler) deregisterServiceAccountInstance(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	params := mux.Vars(r)
	id := params["id"]
	if len(id) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	appID := r.URL.Query().Get("app_id")
	if len(id) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("app_id"), nil, http.StatusBadRequest, false)
	}
	orgID := r.URL.Query().Get("org_id")
	if len(id) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("org_id"), nil, http.StatusBadRequest, false)
	}

	err := h.coreAPIs.Auth.DeregisterServiceAccountInstance(id, appID, orgID)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionDeregister, model.TypeServiceAccount, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h SystemApisHandler) addServiceAccountCredential(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	params := mux.Vars(r)
	id := params["id"]
	if len(id) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorData(logutils.StatusInvalid, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ServiceAccountCredential
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeServiceAccountCredential, nil, err, http.StatusBadRequest, true)
	}

	creds := serviceAccountCredentialFromDef(&requestData)

	creds, err = h.coreAPIs.Auth.AddServiceAccountCredential(id, creds, l)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionInsert, model.TypeServiceAccountCredential, nil, err, http.StatusInternalServerError, true)
	}

	credsResp := serviceAccountCredentialToDef(creds)

	data, err = json.Marshal(credsResp)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeServiceAccountCredential, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

func (h SystemApisHandler) removeServiceAccountCredential(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	params := mux.Vars(r)
	id := params["id"]
	if len(id) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	credID := r.URL.Query().Get("cred_id")
	if credID == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("cred_id"), nil, http.StatusBadRequest, false)
	}

	err := h.coreAPIs.Auth.RemoveServiceAccountCredential(id, credID)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionDelete, model.TypeServiceAccountCredential, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h SystemApisHandler) getApplicationAPIKeys(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("app_id"), nil, http.StatusBadRequest, false)
	}

	apiKeys, err := h.coreAPIs.Auth.GetApplicationAPIKeys(appID)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeAPIKey, nil, err, http.StatusInternalServerError, true)
	}

	responseData := apiKeyListToDef(apiKeys)
	data, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeAPIKey, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

func (h SystemApisHandler) getAPIKeys(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	var apiKeys []model.APIKey
	var err error

	id := r.URL.Query().Get("id")
	if id != "" {
		apiKey, err := h.coreAPIs.Auth.GetAPIKey(id)
		if err != nil {
			return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeAPIKey, nil, err, http.StatusInternalServerError, true)
		}
		if apiKey != nil {
			apiKeys = []model.APIKey{*apiKey}
		}
	} else {
		appID := r.URL.Query().Get("app_id")
		if appID == "" {
			return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id and app_id"), nil, http.StatusBadRequest, false)
		}

		apiKeys, err = h.coreAPIs.Auth.GetApplicationAPIKeys(appID)
		if err != nil {
			return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeAPIKey, nil, err, http.StatusInternalServerError, true)
		}
	}

	responseData := apiKeyListToDef(apiKeys)
	data, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeAPIKey, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

func (h SystemApisHandler) createAPIKey(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.APIKey
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeAPIKey, nil, err, http.StatusBadRequest, true)
	}

	apiKey := apiKeyFromDef(requestData)
	_, err = h.coreAPIs.Auth.CreateAPIKey(apiKey)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionCreate, model.TypeAPIKey, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h SystemApisHandler) updateAPIKey(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorData(logutils.StatusInvalid, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.APIKey
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeAPIKey, nil, err, http.StatusBadRequest, true)
	}

	apiKey := apiKeyFromDef(requestData)
	err = h.coreAPIs.Auth.UpdateAPIKey(apiKey)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypeAPIKey, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h SystemApisHandler) deleteAPIKey(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	id := r.URL.Query().Get("id")
	if id == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	err := h.coreAPIs.Auth.DeleteAPIKey(id)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionDelete, model.TypeAPIKey, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h SystemApisHandler) getApplication(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}
	app, err := h.coreAPIs.System.SysGetApplication(ID)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeApplication, nil, err, http.StatusInternalServerError, true)
	}
	if app == nil {
		return l.HttpResponseErrorData(logutils.StatusMissing, model.TypeApplication, &logutils.FieldArgs{"id": ID}, nil, http.StatusNotFound, false)
	}

	responseData := applicationToDef(*app)
	data, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeApplication, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

// createApplication creates an application
func (h SystemApisHandler) createApplication(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.SystemReqApplications
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeApplication, nil, err, http.StatusBadRequest, true)
	}

	appTypes := make([]model.ApplicationType, 0)
	if requestData.ApplicationTypes != nil {
		for _, at := range *requestData.ApplicationTypes {
			versions := make([]model.Version, 0)
			if at.Versions != nil {
				for _, v := range *at.Versions {
					versionNumbers := model.VersionNumbersFromString(v)
					if versionNumbers != nil {
						versions = append(versions, model.Version{VersionNumbers: *versionNumbers})
					}
				}
			}
			appTypes = append(appTypes, model.ApplicationType{Identifier: at.Identifier, Name: *at.Name, Versions: versions})
		}
	}

	_, err = h.coreAPIs.System.SysCreateApplication(requestData.Name, requestData.MultiTenant, requestData.Admin, requestData.SharedIdentities, appTypes)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionCreate, model.TypeApplication, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h SystemApisHandler) updateApplication(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.SystemReqApplications
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeApplication, nil, err, http.StatusBadRequest, true)
	}

	appTypes := make([]model.ApplicationType, 0)
	if requestData.ApplicationTypes != nil {
		for _, at := range *requestData.ApplicationTypes {
			versions := make([]model.Version, 0)
			if at.Versions != nil {
				for _, v := range *at.Versions {
					versionNumbers := model.VersionNumbersFromString(v)
					if versionNumbers != nil {
						versions = append(versions, model.Version{VersionNumbers: *versionNumbers})
					}
				}
			}
			appTypes = append(appTypes, model.ApplicationType{Identifier: at.Identifier, Name: *at.Name, Versions: versions})
		}
	}

	err = h.coreAPIs.System.SysUpdateApplication(ID, requestData.Name, requestData.MultiTenant, requestData.Admin, requestData.SharedIdentities, appTypes)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypeApplication, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h SystemApisHandler) getApplications(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	applications, err := h.coreAPIs.System.SysGetApplications()
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeApplication, nil, err, http.StatusInternalServerError, true)
	}
	var response []Def.ApplicationFields
	for _, application := range applications {
		r := applicationToDef(application)
		response = append(response, r)
	}

	data, err := json.Marshal(response)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeApplication, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

// createPermission creates an permission
func (h SystemApisHandler) createPermission(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.SystemReqPermissions
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypePermission, nil, err, http.StatusBadRequest, true)
	}

	_, err = h.coreAPIs.System.SysCreatePermission(requestData.Name, requestData.Description, requestData.ServiceId, requestData.Assigners)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionCreate, model.TypePermission, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

// updatePermission updates an permission
func (h SystemApisHandler) updatePermission(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.SystemReqPermissions
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypePermission, nil, err, http.StatusBadRequest, true)
	}

	_, err = h.coreAPIs.System.SysUpdatePermission(requestData.Name, requestData.Description, requestData.ServiceId, requestData.Assigners)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypePermission, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h SystemApisHandler) getApplicationConfigs(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	appTypeIdentifier := r.URL.Query().Get("app_type_id")
	if appTypeIdentifier == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("app_type_id"), nil, http.StatusBadRequest, false)
	}

	var orgIDRef *string
	orgID := r.URL.Query().Get("org_id")
	if len(orgID) > 0 {
		orgIDRef = &orgID
	}

	version := r.URL.Query().Get("version")
	versionNumbers := model.VersionNumbersFromString(version)
	if version != "" && versionNumbers == nil {
		return l.HttpResponseErrorData(logutils.StatusInvalid, logutils.TypeQueryParam, logutils.StringArgs("version"), nil, http.StatusBadRequest, false)
	}

	appConfigs, err := h.coreAPIs.System.SysGetAppConfigs(appTypeIdentifier, orgIDRef, versionNumbers)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeApplicationConfig, nil, err, http.StatusInternalServerError, true)
	}

	appConfigsResp := appConfigsToDef(appConfigs)

	data, err := json.Marshal(appConfigsResp)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeApplicationConfig, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

func (h SystemApisHandler) getApplicationConfig(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	appConfig, err := h.coreAPIs.System.SysGetAppConfig(ID)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypeApplicationConfig, nil, err, http.StatusInternalServerError, true)
	}
	if appConfig == nil {
		return l.HttpResponseErrorData(logutils.StatusMissing, model.TypeApplicationConfig, &logutils.FieldArgs{"id": ID}, nil, http.StatusNotFound, false)
	}

	appConfigResp := appConfigToDef(*appConfig)

	data, err := json.Marshal(appConfigResp)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeApplicationConfig, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

func (h SystemApisHandler) createApplicationConfig(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.SystemReqCreateApplicationConfigRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("appconfig create request"), nil, err, http.StatusBadRequest, true)
	}

	version := model.VersionNumbersFromString(requestData.Version)
	if version == nil {
		return l.HttpResponseErrorData(logutils.StatusInvalid, model.TypeVersionNumbers, nil, nil, http.StatusBadRequest, false)
	}

	_, err = h.coreAPIs.System.SysCreateAppConfig(requestData.AppTypeId, requestData.OrgId, requestData.Data, *version)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionCreate, model.TypeApplicationConfig, nil, err, http.StatusBadRequest, true)
	}

	// data, err = json.Marshal(insertedConfig)
	// if err != nil {
	// 	return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeApplicationConfigs, nil, err, http.StatusInternalServerError, false)
	// }

	// return l.HttpResponseSuccessJSON(data)

	return l.HttpResponseSuccess()
}

func (h SystemApisHandler) updateApplicationConfig(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.SystemReqCreateApplicationConfigRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("appconfig update request"), nil, err, http.StatusBadRequest, true)
	}

	version := model.VersionNumbersFromString(requestData.Version)
	if version == nil {
		return l.HttpResponseErrorData(logutils.StatusInvalid, model.TypeVersionNumbers, nil, nil, http.StatusBadRequest, false)
	}

	err = h.coreAPIs.System.SysUpdateAppConfig(ID, requestData.AppTypeId, requestData.OrgId, requestData.Data, *version)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypeApplicationConfig, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h SystemApisHandler) deleteApplicationConfig(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	err := h.coreAPIs.System.SysDeleteAppConfig(ID)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypeApplicationConfig, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

// createAuthTypes creates auth-type
func (h SystemApisHandler) createAuthTypes(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.SystemReqCreateAuthType
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeOrganization, nil, err, http.StatusBadRequest, true)
	}

	code := requestData.Code
	description := requestData.Description
	isExternal := requestData.IsExternal
	isAnonymous := requestData.IsAnonymous
	useCredentials := requestData.UseCredentials
	ignoreMFA := requestData.IgnoreMfa
	params := requestData.Params

	_, err = h.coreAPIs.System.SysCreateAuthTypes(code, description, isExternal, isAnonymous, useCredentials, ignoreMFA, params.AdditionalProperties)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionCreate, model.TypeAuthType, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

// getAuthTypes gets auth-types
func (h SystemApisHandler) getAuthTypes(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	authTypes, err := h.coreAPIs.System.SysGetAuthTypes()
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeOrganization, nil, err, http.StatusInternalServerError, true)
	}

	response := authTypesToDef(authTypes)

	data, err := json.Marshal(response)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeOrganization, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

// updateAuthTypes updates auth type
func (h SystemApisHandler) updateAuthTypes(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	rParams := mux.Vars(r)
	ID := rParams["id"]
	if len(ID) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorData(logutils.StatusInvalid, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}
	var requestData Def.SystemReqUpdateAuthType
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeOrganization, nil, err, http.StatusBadRequest, true)
	}

	code := requestData.Code
	description := requestData.Description
	isExternal := requestData.IsExternal
	isAnonymous := requestData.IsAnonymous
	useCredentials := requestData.UseCredentials
	ignoreMFA := requestData.IgnoreMfa
	params := requestData.Params

	err = h.coreAPIs.System.SysUpdateAuthTypes(ID, code, description, isExternal, isAnonymous, useCredentials, ignoreMFA, params.AdditionalProperties)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypeAuthType, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

// NewSystemApisHandler creates new system Handler instance
func NewSystemApisHandler(coreAPIs *core.APIs) SystemApisHandler {
	return SystemApisHandler{coreAPIs: coreAPIs}
}
