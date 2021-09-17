package web

import (
	"core-building-block/core"
	"core-building-block/core/auth"
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/rokmetro/logging-library/logs"
	"github.com/rokmetro/logging-library/logutils"
)

//ServicesApisHandler handles the rest APIs implementation
type ServicesApisHandler struct {
	coreAPIs *core.APIs
}

func (h ServicesApisHandler) authLogin(l *logs.Log, r *http.Request) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ReqLoginRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("auth login request"), nil, err, http.StatusBadRequest, true)
	}

	requestCreds, err := interfaceToJSON(requestData.Creds)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, "creds", nil, err, http.StatusBadRequest, true)
	}

	requestParams, err := interfaceToJSON(requestData.Params)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, "params", nil, err, http.StatusBadRequest, true)
	}

	accessToken, refreshToken, account, params, err := h.coreAPIs.Auth.Login(string(requestData.AuthType), requestCreds, requestData.AppId, requestData.OrgId, requestParams, l)
	if err != nil {
		return l.HttpResponseError("Error logging in", err, http.StatusInternalServerError, true)
	}

	tokenType := Def.ResSharedRokwireTokenTokenTypeBearer
	rokwireToken := Def.ResSharedRokwireToken{AccessToken: &accessToken, RefreshToken: &refreshToken, TokenType: &tokenType}

	///prepare response
	//profile
	profile := profileToDef(&account.Profile)
	//permissions
	permissions := applicationPermissionsToDef(account.Permissions)
	//roles
	roles := applicationRolesToDef(account.Roles)
	//groups
	groups := applicationGroupsToDef(account.Groups)
	//account auth types
	accountAuthTypes := accountAuthTypesToDef(account.AuthTypes)
	accountData := Def.ResLoginAccount{Id: account.ID, Permissions: &permissions, Roles: &roles, Groups: &groups, AuthTypes: &accountAuthTypes, Profile: profile}

	responseData := &Def.ResLoginResponse{Token: &rokwireToken, Account: &accountData, Params: &params}
	respData, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, logutils.MessageDataType("auth login response"), nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(respData)
}

func (h ServicesApisHandler) authRefresh(l *logs.Log, r *http.Request) logs.HttpResponse {
	requestData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	accessToken, refreshToken, params, err := h.coreAPIs.Auth.Refresh(string(requestData), l)
	if err != nil {
		return l.HttpResponseError("Error refreshing token", err, http.StatusInternalServerError, true)
	}

	tokenType := Def.ResSharedRokwireTokenTokenTypeBearer
	rokwireToken := Def.ResSharedRokwireToken{AccessToken: &accessToken, RefreshToken: &refreshToken, TokenType: &tokenType}
	responseData := &Def.ResRefreshResponse{Token: &rokwireToken, Params: &params}
	respData, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, logutils.MessageDataType("auth refresh response"), nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(respData)
}

func (h ServicesApisHandler) authLoginURL(l *logs.Log, r *http.Request) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ReqLoginUrlRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, "auth login url request", nil, err, http.StatusBadRequest, true)
	}

	loginURL, params, err := h.coreAPIs.Auth.GetLoginURL(string(requestData.AuthType), requestData.AppId, requestData.OrgId, requestData.RedirectUri, l)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, "login url", nil, err, http.StatusInternalServerError, true)
	}

	responseData := &Def.ResLoginUrlResponse{LoginUrl: loginURL, Params: &params}
	respData, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, "auth login url response", nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(respData)
}

func (h ServicesApisHandler) authAuthorizeService(l *logs.Log, r *http.Request) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ReqAuthorizeServiceRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, "auth authorize service request", nil, err, http.StatusBadRequest, true)
	}

	scopes, err := scopeListFromDef(requestData.ApprovedScopes)
	if err != nil {
		return l.HttpResponseErrorData(logutils.StatusInvalid, "scopes", nil, err, http.StatusBadRequest, true)
	}

	//TODO: Fill "claims" with claims from access token
	token, tokenScopes, reg, err := h.coreAPIs.Auth.AuthorizeService(auth.TokenClaims{}, requestData.ServiceId, scopes, l)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, "login url", nil, err, http.StatusInternalServerError, true)
	}

	scopesResp := scopeListToDef(tokenScopes)
	regResp := serviceRegToDef(reg)
	tokenType := Def.ResAuthorizeServiceResponseTokenTypeBearer

	responseData := &Def.ResAuthorizeServiceResponse{AccessToken: &token, TokenType: &tokenType, ApprovedScopes: &scopesResp, ServiceReg: regResp}
	respData, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, "auth login url response", nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(respData)
}

func (h ServicesApisHandler) getServiceRegistrations(l *logs.Log, r *http.Request) logs.HttpResponse {
	serviceIDsParam := r.URL.Query().Get("ids")
	if serviceIDsParam == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("ids"), nil, http.StatusBadRequest, false)
	}
	serviceIDs := strings.Split(serviceIDsParam, ",")

	serviceRegs, err := h.coreAPIs.Auth.GetServiceRegistrations(serviceIDs)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeServiceReg, nil, err, http.StatusInternalServerError, true)
	}

	serviceRegResp := serviceRegListToDef(serviceRegs)

	data, err := json.Marshal(serviceRegResp)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeServiceReg, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

//getCommonTest TODO get test
func (h ServicesApisHandler) getTest(l *logs.Log, r *http.Request) logs.HttpResponse {
	res := h.coreAPIs.Services.SerGetCommonTest(l)

	return l.HttpResponseSuccessMessage(res)
}

func (h ServicesApisHandler) createAnonymousProfile(l *logs.Log, r *http.Request) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.AnonymousProfile
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeAnonymousProfile, nil, err, http.StatusBadRequest, true)
	}
	profile := anonymousProfileFromDef(&requestData)
	if profile.ID == "" {
		return l.HttpResponseErrorAction(logutils.ActionCast, model.TypeAnonymousProfile, nil, err, http.StatusInternalServerError, true)
	}
	//Update the anonymous profile embedded in accounts collection
	userAnonymousProfile := model.UserAnonymousProfile{ID: profile.ID, Interests: profile.Interests, Favorites: profile.Favorites, Over13: profile.Over13, PositiveInterestTags: profile.PositiveInterestTags, NegativeInterestTags: profile.NegativeInterestTags, CreationDate: profile.CreationDate, LastModifiedDate: profile.LastModifiedDate, PrivacySettings: profile.PrivacySettings}
	err = h.coreAPIs.Services.UpdateUserAnonymousProfile(l, profile.ID, &userAnonymousProfile)
	if err != nil {
		l.LogError("Failed to update anonymous profile in accounts coll", err)
	}
	_, err = h.coreAPIs.Services.CreateAnonymousProfile(l, &profile)
	if err != nil {
		l.HttpResponseErrorAction(logutils.ActionCreate, model.TypeAnonymousProfile, nil, err, http.StatusInternalServerError, true)
	}
	return l.HttpResponseSuccess()
}

func (h ServicesApisHandler) updateAnonymousProfile(l *logs.Log, r *http.Request) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.AnonymousProfile
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeAnonymousProfile, nil, err, http.StatusBadRequest, true)
	}
	profile := anonymousProfileFromDef(&requestData)
	if profile.ID == "" {
		return l.HttpResponseErrorAction(logutils.ActionCast, model.TypeAnonymousProfile, nil, err, http.StatusInternalServerError, true)
	}
	//Update the anonymous profile embedded in accounts collection
	userAnonymousProfile := model.UserAnonymousProfile{ID: profile.ID, Interests: profile.Interests, Favorites: profile.Favorites, Over13: profile.Over13, PositiveInterestTags: profile.PositiveInterestTags, NegativeInterestTags: profile.NegativeInterestTags, CreationDate: profile.CreationDate, LastModifiedDate: profile.LastModifiedDate, PrivacySettings: profile.PrivacySettings}
	err = h.coreAPIs.Services.UpdateUserAnonymousProfile(l, profile.ID, &userAnonymousProfile)
	if err != nil {
		l.LogError("Failed to update anonymous profile in accounts coll", err)
	}
	err = h.coreAPIs.Services.UpdateAnonymousProfile(l, profile.ID, &profile.Favorites, &profile.Interests, &profile.NegativeInterestTags, &profile.PositiveInterestTags, &profile.PrivacySettings, &profile.Over13)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypeAnonymousProfile, nil, err, http.StatusInternalServerError, true)
	}
	return l.HttpResponseSuccess()
}

func (h ServicesApisHandler) getAnonymousProfile(l *logs.Log, r *http.Request) logs.HttpResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	profile, err := h.coreAPIs.Services.GetAnonymousProfile(l, ID)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeAnonymousProfile, nil, err, http.StatusInternalServerError, true)
	}

	data, err := json.Marshal(profile)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeAnonymousProfile, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

func (h ServicesApisHandler) deleteAnonymousProfile(l *logs.Log, r *http.Request) logs.HttpResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}
	userAnonymousProfile := model.UserAnonymousProfile{}
	err := h.coreAPIs.Services.UpdateUserAnonymousProfile(l, ID, &userAnonymousProfile)
	if err != nil {
		l.LogError("Failed to update anonymous profile in accounts coll", err)
	}

	err = h.coreAPIs.Services.DeleteAnonymousProfile(l, ID)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionDelete, model.TypeAnonymousProfile, nil, err, http.StatusInternalServerError, true)
	}
	return l.HttpResponseSuccess()
}

//NewServicesApisHandler creates new rest services Handler instance
func NewServicesApisHandler(coreAPIs *core.APIs) ServicesApisHandler {
	return ServicesApisHandler{coreAPIs: coreAPIs}
}
