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
	"github.com/rokwire/core-auth-library-go/v2/authorization"
	"github.com/rokwire/core-auth-library-go/v2/tokenauth"
	"github.com/rokwire/logging-library-go/v2/logs"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

// SystemApisHandler handles system APIs implementation
type SystemApisHandler struct {
	coreAPIs *core.APIs
}

func (h SystemApisHandler) getAppOrgToken(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("app_id"), nil, http.StatusBadRequest, false)
	}
	orgID := r.URL.Query().Get("org_id")
	if orgID == "" {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("org_id"), nil, http.StatusBadRequest, false)
	}

	token, err := h.coreAPIs.Auth.GetAdminToken(*claims, appID, orgID, l)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionGet, "app org token", nil, err, http.StatusInternalServerError, true)
	}

	response := Def.AdminToken{Token: token}
	responseJSON, err := json.Marshal(response)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, "app org token", nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(responseJSON)
}

// getConfig gets config by id
func (h SystemApisHandler) getConfig(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	id := params["id"]
	if len(id) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypePathParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	config, err := h.coreAPIs.System.SysGetConfig(id)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionGet, model.TypeConfig, nil, err, http.StatusInternalServerError, true)
	}
	if config == nil {
		return l.HTTPResponseErrorData(logutils.StatusMissing, model.TypeConfig, &logutils.FieldArgs{"id": id}, nil, http.StatusNotFound, true)
	}

	data, err := json.Marshal(configToDef(*config))
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeConfig, nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(data)
}

// createConfig creates a config by id
func (h SystemApisHandler) createConfig(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	id := params["id"]
	if len(id) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypePathParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	var requestData Def.Config
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, true)
	}

	config := configFromDef(requestData, id)
	err = h.coreAPIs.System.SysCreateConfig(config)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionCreate, model.TypeConfig, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

// updateConfig updates a config by id
func (h SystemApisHandler) updateConfig(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	id := params["id"]
	if len(id) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypePathParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	var requestData Def.Config
	err := json.NewDecoder(r.Body).Decode(&requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, true)
	}

	config := configFromDef(requestData, id)
	err = h.coreAPIs.System.SysUpdateConfig(config)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUpdate, model.TypeConfig, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

// deleteConfig deletes a config by id
func (h SystemApisHandler) deleteConfig(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	id := params["id"]
	if len(id) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypePathParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	err := h.coreAPIs.System.SysDeleteConfig(id)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionDelete, model.TypeConfig, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

// getApplicationOrganization retrieves app-org for specified id
func (h SystemApisHandler) getApplicationOrganization(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	appOrg, err := h.coreAPIs.System.SysGetApplicationOrganization(ID)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUpdate, model.TypeApplicationOrganization, nil, err, http.StatusInternalServerError, true)
	}

	responseData := appOrgToDef(appOrg)
	data, err := json.Marshal(responseData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeApplicationOrganization, nil, err, http.StatusInternalServerError, false)
	}
	return l.HTTPResponseSuccessJSON(data)
}

// getApplicationOrganizations retrieves all app-orgs matching the provided query
func (h SystemApisHandler) getApplicationOrganizations(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	var appID *string
	appIDRaw := r.URL.Query().Get("app_id")
	if appIDRaw != "" {
		appID = &appIDRaw
	}

	var orgID *string
	orgIDRaw := r.URL.Query().Get("org_id")
	if orgIDRaw != "" {
		orgID = &orgIDRaw
	}

	appOrgs, err := h.coreAPIs.System.SysGetApplicationOrganizations(appID, orgID)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUpdate, model.TypeApplicationOrganization, nil, err, http.StatusInternalServerError, true)
	}

	responseData := appOrgsToDef(appOrgs)
	data, err := json.Marshal(responseData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeApplicationOrganization, nil, err, http.StatusInternalServerError, false)
	}
	return l.HTTPResponseSuccessJSON(data)
}

// createApplicationOrganization creates applicationOrganization
func (h SystemApisHandler) createApplicationOrganization(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorData(logutils.StatusInvalid, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}
	var requestData Def.ApplicationOrganization
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypeApplicationOrganization, nil, err, http.StatusBadRequest, true)
	}

	//TODO: Fix missing supported auth types, expire policies,
	appOrg := appOrgFromDef(&requestData)
	_, err = h.coreAPIs.System.SysCreateApplicationOrganization(requestData.AppId, requestData.OrgId, *appOrg)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUpdate, model.TypeApplicationOrganization, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

// updateApplicationOrganization updates applicationOrganization
func (h SystemApisHandler) updateApplicationOrganization(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorData(logutils.StatusInvalid, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}
	var requestData Def.ApplicationOrganization
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypeApplicationOrganization, nil, err, http.StatusBadRequest, true)
	}

	updateAppOrg := appOrgFromDef(&requestData)
	updateAppOrg.ID = ID
	err = h.coreAPIs.System.SysUpdateApplicationOrganization(*updateAppOrg)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUpdate, model.TypeApplicationOrganization, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

// createOrganization creates organization
func (h SystemApisHandler) createOrganization(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.Organization
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypeOrganization, nil, err, http.StatusBadRequest, true)
	}

	name := requestData.Name
	types := requestData.Type

	var domains []string
	if requestData.Config != nil {
		domains = requestData.Config.Domains
	}

	_, err = h.coreAPIs.System.SysCreateOrganization(name, string(types), domains)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionCreate, model.TypeOrganization, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

// updateOrganization updates organization
func (h SystemApisHandler) updateOrganization(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorData(logutils.StatusInvalid, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}
	var requestData Def.Organization
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypeOrganization, nil, err, http.StatusBadRequest, true)
	}

	name := requestData.Name
	requestType := requestData.Type

	var domains []string
	if requestData.Config != nil {
		domains = requestData.Config.Domains
	}

	err = h.coreAPIs.System.SysUpdateOrganization(ID, name, string(requestType), domains)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUpdate, model.TypeOrganization, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

// getOrganization gets organization
func (h SystemApisHandler) getOrganization(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}
	org, err := h.coreAPIs.System.SysGetOrganization(ID)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionGet, model.TypeOrganization, nil, err, http.StatusInternalServerError, true)
	}
	if org == nil {
		return l.HTTPResponseErrorData(logutils.StatusMissing, model.TypeOrganization, &logutils.FieldArgs{"id": ID}, nil, http.StatusNotFound, false)
	}

	responseData := organizationToDef(org)
	data, err := json.Marshal(responseData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeOrganization, nil, err, http.StatusInternalServerError, false)
	}
	return l.HTTPResponseSuccessJSON(data)
}

// getOrganizations gets organizations
func (h SystemApisHandler) getOrganizations(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	organizations, err := h.coreAPIs.System.SysGetOrganizations()
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionGet, model.TypeOrganization, nil, err, http.StatusInternalServerError, true)
	}

	response := organizationsToDef(organizations)

	data, err := json.Marshal(response)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeOrganization, nil, err, http.StatusInternalServerError, false)
	}
	return l.HTTPResponseSuccessJSON(data)
}

func (h SystemApisHandler) getServiceRegistrations(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	serviceIDsParam := r.URL.Query().Get("ids")
	if serviceIDsParam == "" {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("ids"), nil, http.StatusBadRequest, false)
	}
	serviceIDs := strings.Split(serviceIDsParam, ",")

	serviceRegs := h.coreAPIs.Auth.GetServiceRegistrations(serviceIDs)
	serviceRegResp := serviceRegListToDef(serviceRegs)

	data, err := json.Marshal(serviceRegResp)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeServiceReg, nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(data)
}

func (h SystemApisHandler) registerService(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ServiceReg
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypeServiceReg, nil, err, http.StatusBadRequest, true)
	}

	serviceReg, err := serviceRegFromDef(&requestData)
	if err != nil {
		return l.HTTPResponseErrorData(logutils.StatusInvalid, model.TypeServiceReg, nil, err, http.StatusBadRequest, true)
	}

	err = h.coreAPIs.Auth.RegisterService(serviceReg)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionCreate, model.TypeServiceReg, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

func (h SystemApisHandler) updateServiceRegistration(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorData(logutils.StatusInvalid, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ServiceReg
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypeServiceReg, nil, err, http.StatusBadRequest, true)
	}

	serviceReg, err := serviceRegFromDef(&requestData)
	if err != nil {
		return l.HTTPResponseErrorData(logutils.StatusInvalid, model.TypeServiceReg, nil, err, http.StatusBadRequest, true)
	}

	err = h.coreAPIs.Auth.UpdateServiceRegistration(serviceReg)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUpdate, model.TypeServiceReg, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

func (h SystemApisHandler) deregisterService(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	serviceID := r.URL.Query().Get("id")
	if serviceID == "" {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	err := h.coreAPIs.Auth.DeregisterService(serviceID)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionDelete, model.TypeServiceReg, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

func (h SystemApisHandler) getServiceAccounts(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
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
	if query.Get("scopes") != "" {
		scopeList := strings.Split(query.Get("scopes"), ",")
		scopes, err := authorization.ScopesFromStrings(scopeList, false)
		if err != nil {
			return l.HTTPResponseErrorAction(logutils.ActionParse, model.TypeScope, nil, err, http.StatusInternalServerError, true)
		}
		searchParams["scopes"] = scopes
	}

	serviceAccounts, err := h.coreAPIs.Auth.GetServiceAccounts(searchParams)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionGet, model.TypeServiceAccount, nil, err, http.StatusInternalServerError, true)
	}

	serviceAccountsResp := serviceAccountListToDef(serviceAccounts)

	data, err := json.Marshal(serviceAccountsResp)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeServiceAccount, nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(data)
}

func (h SystemApisHandler) registerServiceAccount(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	fromAppID := utils.StringOrNil(r.URL.Query().Get("app_id"), "")
	fromOrgID := utils.StringOrNil(r.URL.Query().Get("org_id"), "")

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorData(logutils.StatusInvalid, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ServiceAccount
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypeServiceAccount, nil, err, http.StatusBadRequest, true)
	}

	var scopes []authorization.Scope
	if requestData.Scopes != nil && *requestData.Scopes != nil {
		scopes, err = authorization.ScopesFromStrings(*requestData.Scopes, false)
		if err != nil {
			return l.HTTPResponseErrorAction(logutils.ActionParse, model.TypeScope, nil, err, http.StatusInternalServerError, true)
		}
	}

	var creds []model.ServiceAccountCredential
	if requestData.Creds != nil {
		creds = serviceAccountCredentialListFromDef(*requestData.Creds)
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	serviceAccount, err := h.coreAPIs.Auth.RegisterServiceAccount(requestData.AccountId, fromAppID, fromOrgID, requestData.Name,
		requestData.AppId, requestData.OrgId, requestData.Permissions, scopes, requestData.FirstParty, creds, assignerPermissions, l)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRegister, model.TypeServiceAccount, nil, err, http.StatusInternalServerError, true)
	}

	serviceAccountResp := serviceAccountToDef(serviceAccount)

	data, err = json.Marshal(serviceAccountResp)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeServiceAccount, nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(data)
}

func (h SystemApisHandler) deregisterServiceAccount(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	accountID := r.URL.Query().Get("account_id")
	if accountID == "" {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("account_id"), nil, http.StatusBadRequest, false)
	}

	err := h.coreAPIs.Auth.DeregisterServiceAccount(accountID)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionDeregister, model.TypeServiceAccount, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

func (h SystemApisHandler) getServiceAccountInstance(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	id := params["id"]
	if len(id) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	appID := r.URL.Query().Get("app_id")
	if len(id) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("app_id"), nil, http.StatusBadRequest, false)
	}
	orgID := r.URL.Query().Get("org_id")
	if len(id) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("org_id"), nil, http.StatusBadRequest, false)
	}

	serviceAccount, err := h.coreAPIs.Auth.GetServiceAccountInstance(id, appID, orgID)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionGet, model.TypeServiceAccount, nil, err, http.StatusInternalServerError, true)
	}

	serviceAccountResp := serviceAccountToDef(serviceAccount)

	data, err := json.Marshal(serviceAccountResp)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeServiceAccount, nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(data)
}

func (h SystemApisHandler) updateServiceAccountInstance(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	id := params["id"]
	if len(id) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	appID := r.URL.Query().Get("app_id")
	if len(id) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("app_id"), nil, http.StatusBadRequest, false)
	}
	orgID := r.URL.Query().Get("org_id")
	if len(id) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("org_id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorData(logutils.StatusInvalid, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.SystemReqUpdateServiceAccount
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, "service account update request", nil, err, http.StatusBadRequest, true)
	}

	var scopes []authorization.Scope
	if requestData.Scopes != nil && *requestData.Scopes != nil {
		scopes, err = authorization.ScopesFromStrings(*requestData.Scopes, false)
		if err != nil {
			return l.HTTPResponseErrorAction(logutils.ActionParse, model.TypeScope, nil, err, http.StatusInternalServerError, true)
		}
	}

	assignerPermissions := strings.Split(claims.Permissions, ",")
	serviceAccount, err := h.coreAPIs.Auth.UpdateServiceAccountInstance(id, appID, orgID, requestData.Name, requestData.Permissions, scopes, assignerPermissions)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUpdate, model.TypeServiceAccount, nil, err, http.StatusInternalServerError, true)
	}

	serviceAccountResp := serviceAccountToDef(serviceAccount)

	data, err = json.Marshal(serviceAccountResp)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeServiceAccount, nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(data)
}

func (h SystemApisHandler) deregisterServiceAccountInstance(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	id := params["id"]
	if len(id) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	appID := r.URL.Query().Get("app_id")
	if len(id) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("app_id"), nil, http.StatusBadRequest, false)
	}
	orgID := r.URL.Query().Get("org_id")
	if len(id) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("org_id"), nil, http.StatusBadRequest, false)
	}

	err := h.coreAPIs.Auth.DeregisterServiceAccountInstance(id, appID, orgID)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionDeregister, model.TypeServiceAccount, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

func (h SystemApisHandler) addServiceAccountCredential(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	id := params["id"]
	if len(id) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorData(logutils.StatusInvalid, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ServiceAccountCredential
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypeServiceAccountCredential, nil, err, http.StatusBadRequest, true)
	}

	creds := serviceAccountCredentialFromDef(&requestData)

	creds, err = h.coreAPIs.Auth.AddServiceAccountCredential(id, creds, l)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionInsert, model.TypeServiceAccountCredential, nil, err, http.StatusInternalServerError, true)
	}

	credsResp := serviceAccountCredentialToDef(creds)

	data, err = json.Marshal(credsResp)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeServiceAccountCredential, nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(data)
}

func (h SystemApisHandler) removeServiceAccountCredential(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	id := params["id"]
	if len(id) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	credID := r.URL.Query().Get("cred_id")
	if credID == "" {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("cred_id"), nil, http.StatusBadRequest, false)
	}

	err := h.coreAPIs.Auth.RemoveServiceAccountCredential(id, credID)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionDelete, model.TypeServiceAccountCredential, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

func (h SystemApisHandler) getApplicationAPIKeys(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	appID := r.URL.Query().Get("app_id")
	if appID == "" {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("app_id"), nil, http.StatusBadRequest, false)
	}

	apiKeys, err := h.coreAPIs.Auth.GetApplicationAPIKeys(appID)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionGet, model.TypeAPIKey, nil, err, http.StatusInternalServerError, true)
	}

	responseData := apiKeyListToDef(apiKeys)
	data, err := json.Marshal(responseData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeAPIKey, nil, err, http.StatusInternalServerError, false)
	}
	return l.HTTPResponseSuccessJSON(data)
}

func (h SystemApisHandler) getAPIKeys(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	var apiKeys []model.APIKey
	var err error

	id := r.URL.Query().Get("id")
	if id != "" {
		apiKey, err := h.coreAPIs.Auth.GetAPIKey(id)
		if err != nil {
			return l.HTTPResponseErrorAction(logutils.ActionGet, model.TypeAPIKey, nil, err, http.StatusInternalServerError, true)
		}
		if apiKey != nil {
			apiKeys = []model.APIKey{*apiKey}
		}
	} else {
		appID := r.URL.Query().Get("app_id")
		if appID == "" {
			return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id and app_id"), nil, http.StatusBadRequest, false)
		}

		apiKeys, err = h.coreAPIs.Auth.GetApplicationAPIKeys(appID)
		if err != nil {
			return l.HTTPResponseErrorAction(logutils.ActionGet, model.TypeAPIKey, nil, err, http.StatusInternalServerError, true)
		}
	}

	responseData := apiKeyListToDef(apiKeys)
	data, err := json.Marshal(responseData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeAPIKey, nil, err, http.StatusInternalServerError, false)
	}
	return l.HTTPResponseSuccessJSON(data)
}

func (h SystemApisHandler) createAPIKey(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.APIKey
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypeAPIKey, nil, err, http.StatusBadRequest, true)
	}

	apiKey := apiKeyFromDef(requestData)
	_, err = h.coreAPIs.Auth.CreateAPIKey(apiKey)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionCreate, model.TypeAPIKey, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

func (h SystemApisHandler) updateAPIKey(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorData(logutils.StatusInvalid, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.APIKey
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypeAPIKey, nil, err, http.StatusBadRequest, true)
	}

	apiKey := apiKeyFromDef(requestData)
	err = h.coreAPIs.Auth.UpdateAPIKey(apiKey)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUpdate, model.TypeAPIKey, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

func (h SystemApisHandler) deleteAPIKey(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	id := r.URL.Query().Get("id")
	if id == "" {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	err := h.coreAPIs.Auth.DeleteAPIKey(id)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionDelete, model.TypeAPIKey, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

func (h SystemApisHandler) getApplication(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}
	app, err := h.coreAPIs.System.SysGetApplication(ID)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionGet, model.TypeApplication, nil, err, http.StatusInternalServerError, true)
	}
	if app == nil {
		return l.HTTPResponseErrorData(logutils.StatusMissing, model.TypeApplication, &logutils.FieldArgs{"id": ID}, nil, http.StatusNotFound, false)
	}

	responseData := applicationToDef(*app)
	data, err := json.Marshal(responseData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeApplication, nil, err, http.StatusInternalServerError, false)
	}
	return l.HTTPResponseSuccessJSON(data)
}

// createApplication creates an application
func (h SystemApisHandler) createApplication(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.Application
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypeApplication, nil, err, http.StatusBadRequest, true)
	}

	appTypes := make([]model.ApplicationType, 0)
	if requestData.Types != nil {
		appTypes = applicationTypeListFromDef(*requestData.Types)
	}

	_, err = h.coreAPIs.System.SysCreateApplication(requestData.Name, requestData.MultiTenant, requestData.Admin, requestData.SharedIdentities, appTypes)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionCreate, model.TypeApplication, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

func (h SystemApisHandler) updateApplication(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.Application
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypeApplication, nil, err, http.StatusBadRequest, true)
	}

	appTypes := make([]model.ApplicationType, 0)
	if requestData.Types != nil {
		appTypes = applicationTypeListFromDef(*requestData.Types)
	}

	err = h.coreAPIs.System.SysUpdateApplication(ID, requestData.Name, requestData.MultiTenant, requestData.Admin, requestData.SharedIdentities, appTypes)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUpdate, model.TypeApplication, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

func (h SystemApisHandler) getApplications(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	applications, err := h.coreAPIs.System.SysGetApplications()
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionGet, model.TypeApplication, nil, err, http.StatusInternalServerError, true)
	}
	response := applicationsToDef(applications)

	data, err := json.Marshal(response)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeApplication, nil, err, http.StatusInternalServerError, false)
	}
	return l.HTTPResponseSuccessJSON(data)
}

// createPermission creates an permission
func (h SystemApisHandler) createPermission(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.Permission
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypePermission, nil, err, http.StatusBadRequest, true)
	}

	_, err = h.coreAPIs.System.SysCreatePermission(requestData.Name, requestData.Description, requestData.ServiceId, requestData.Assigners)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionCreate, model.TypePermission, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

// updatePermission updates an permission
func (h SystemApisHandler) updatePermission(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.Permission
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypePermission, nil, err, http.StatusBadRequest, true)
	}

	_, err = h.coreAPIs.System.SysUpdatePermission(requestData.Name, requestData.Description, requestData.ServiceId, requestData.Assigners)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUpdate, model.TypePermission, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

func (h SystemApisHandler) getApplicationConfigs(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	appTypeIdentifier := r.URL.Query().Get("app_type_id")
	if appTypeIdentifier == "" {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("app_type_id"), nil, http.StatusBadRequest, false)
	}

	var orgIDRef *string
	orgID := r.URL.Query().Get("org_id")
	if len(orgID) > 0 {
		orgIDRef = &orgID
	}

	version := r.URL.Query().Get("version")
	versionNumbers := model.VersionNumbersFromString(version)
	if version != "" && versionNumbers == nil {
		return l.HTTPResponseErrorData(logutils.StatusInvalid, logutils.TypeQueryParam, logutils.StringArgs("version"), nil, http.StatusBadRequest, false)
	}

	appConfigs, err := h.coreAPIs.System.SysGetAppConfigs(appTypeIdentifier, orgIDRef, versionNumbers)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionGet, model.TypeApplicationConfig, nil, err, http.StatusInternalServerError, true)
	}

	appConfigsResp := appConfigsToDef(appConfigs)

	data, err := json.Marshal(appConfigsResp)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeApplicationConfig, nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(data)
}

func (h SystemApisHandler) getApplicationConfig(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	appConfig, err := h.coreAPIs.System.SysGetAppConfig(ID)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUpdate, model.TypeApplicationConfig, nil, err, http.StatusInternalServerError, true)
	}
	if appConfig == nil {
		return l.HTTPResponseErrorData(logutils.StatusMissing, model.TypeApplicationConfig, &logutils.FieldArgs{"id": ID}, nil, http.StatusNotFound, false)
	}

	appConfigResp := appConfigToDef(*appConfig)

	data, err := json.Marshal(appConfigResp)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeApplicationConfig, nil, err, http.StatusInternalServerError, false)
	}

	return l.HTTPResponseSuccessJSON(data)
}

func (h SystemApisHandler) createApplicationConfig(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ApplicationConfig
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("appconfig create request"), nil, err, http.StatusBadRequest, true)
	}

	version := model.VersionNumbersFromString(requestData.Version)
	if version == nil {
		return l.HTTPResponseErrorData(logutils.StatusInvalid, model.TypeVersionNumbers, nil, nil, http.StatusBadRequest, false)
	}

	_, err = h.coreAPIs.System.SysCreateAppConfig(requestData.AppTypeId, requestData.OrgId, requestData.Data, *version)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionCreate, model.TypeApplicationConfig, nil, err, http.StatusBadRequest, true)
	}

	// data, err = json.Marshal(insertedConfig)
	// if err != nil {
	// 	return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeApplicationConfigs, nil, err, http.StatusInternalServerError, false)
	// }

	// return l.HTTPResponseSuccessJSON(data)

	return l.HTTPResponseSuccess()
}

func (h SystemApisHandler) updateApplicationConfig(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ApplicationConfig
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("appconfig update request"), nil, err, http.StatusBadRequest, true)
	}

	version := model.VersionNumbersFromString(requestData.Version)
	if version == nil {
		return l.HTTPResponseErrorData(logutils.StatusInvalid, model.TypeVersionNumbers, nil, nil, http.StatusBadRequest, false)
	}

	err = h.coreAPIs.System.SysUpdateAppConfig(ID, requestData.AppTypeId, requestData.OrgId, requestData.Data, *version)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUpdate, model.TypeApplicationConfig, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

func (h SystemApisHandler) deleteApplicationConfig(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	err := h.coreAPIs.System.SysDeleteAppConfig(ID)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUpdate, model.TypeApplicationConfig, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

// createAuthTypes creates auth-type
func (h SystemApisHandler) createAuthTypes(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.AuthType
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypeOrganization, nil, err, http.StatusBadRequest, true)
	}

	code := requestData.Code
	description := requestData.Description
	isExternal := requestData.IsExternal
	isAnonymous := requestData.IsAnonymous
	useCredentials := requestData.UseCredentials
	ignoreMFA := requestData.IgnoreMfa
	var params map[string]interface{}
	if requestData.Params != nil {
		params = requestData.Params.AdditionalProperties
	}

	_, err = h.coreAPIs.System.SysCreateAuthTypes(code, description, isExternal, isAnonymous, useCredentials, ignoreMFA, params)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionCreate, model.TypeAuthType, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

// getAuthTypes gets auth-types
func (h SystemApisHandler) getAuthTypes(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	authTypes, err := h.coreAPIs.System.SysGetAuthTypes()
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionGet, model.TypeOrganization, nil, err, http.StatusInternalServerError, true)
	}

	response := authTypesToDef(authTypes)

	data, err := json.Marshal(response)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionMarshal, model.TypeOrganization, nil, err, http.StatusInternalServerError, false)
	}
	return l.HTTPResponseSuccessJSON(data)
}

// updateAuthTypes updates auth type
func (h SystemApisHandler) updateAuthTypes(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HTTPResponse {
	rParams := mux.Vars(r)
	ID := rParams["id"]
	if len(ID) <= 0 {
		return l.HTTPResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HTTPResponseErrorData(logutils.StatusInvalid, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}
	var requestData Def.AuthType
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUnmarshal, model.TypeOrganization, nil, err, http.StatusBadRequest, true)
	}

	code := requestData.Code
	description := requestData.Description
	isExternal := requestData.IsExternal
	isAnonymous := requestData.IsAnonymous
	useCredentials := requestData.UseCredentials
	ignoreMFA := requestData.IgnoreMfa
	var params map[string]interface{}
	if requestData.Params != nil {
		params = requestData.Params.AdditionalProperties
	}

	err = h.coreAPIs.System.SysUpdateAuthTypes(ID, code, description, isExternal, isAnonymous, useCredentials, ignoreMFA, params)
	if err != nil {
		return l.HTTPResponseErrorAction(logutils.ActionUpdate, model.TypeAuthType, nil, err, http.StatusInternalServerError, true)
	}

	return l.HTTPResponseSuccess()
}

// NewSystemApisHandler creates new system Handler instance
func NewSystemApisHandler(coreAPIs *core.APIs) SystemApisHandler {
	return SystemApisHandler{coreAPIs: coreAPIs}
}
