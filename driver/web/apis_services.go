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
	log "github.com/rokmetro/logging-library/loglib"
)

const (
	//TypeUserAuth user auth type
	TypeAnonymousProfile log.LogData = "anonymous profile"
)

//ServicesApisHandler handles the rest APIs implementation
type ServicesApisHandler struct {
	coreAPIs *core.APIs
}

func (h ServicesApisHandler) authLogin(l *log.Log, r *http.Request) log.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionRead, log.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.AuthLoginRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionUnmarshal, log.LogData("auth login request"), nil, err, http.StatusBadRequest, true)
	}

	requestCreds, err := interfaceToJSON(requestData.Creds)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionMarshal, "creds", nil, err, http.StatusBadRequest, true)
	}

	requestParams, err := interfaceToJSON(requestData.Params)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionMarshal, "params", nil, err, http.StatusBadRequest, true)
	}

	accessToken, refreshToken, user, err := h.coreAPIs.Auth.Login(string(requestData.AuthType), requestCreds, requestData.OrgId, requestData.AppId, requestParams, l)
	if err != nil {
		return l.HttpResponseError("Error logging in", err, http.StatusInternalServerError, true)
	}

	tokenType := Def.AuthLoginResponseTokenTypeBearer
	responseData := &Def.AuthLoginResponse{AccessToken: &accessToken, User: userToDef(user), RefreshToken: &refreshToken, TokenType: &tokenType}
	respData, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionMarshal, log.LogData("auth login response"), nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(respData)
}

func (h ServicesApisHandler) authRefresh(l *log.Log, r *http.Request) log.HttpResponse {
	requestData, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionRead, log.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	accessToken, refreshToken, err := h.coreAPIs.Auth.Refresh(string(requestData), l)
	if err != nil {
		return l.HttpResponseError("Error refreshing token", err, http.StatusInternalServerError, true)
	}

	responseData := &Def.AuthRefreshResponse{AccessToken: &accessToken, RefreshToken: &refreshToken}
	respData, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionMarshal, log.LogData("auth refresh response"), nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(respData)
}

func (h ServicesApisHandler) authLoginURL(l *log.Log, r *http.Request) log.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionRead, log.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.AuthLoginUrlRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionUnmarshal, log.LogData("auth login url request"), nil, err, http.StatusBadRequest, true)
	}

	loginURL, params, err := h.coreAPIs.Auth.GetLoginURL(string(requestData.AuthType), requestData.OrgId, requestData.AppId, requestData.RedirectUri, l)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionGet, "login url", nil, err, http.StatusInternalServerError, true)
	}

	responseData := &Def.AuthLoginUrlResponse{LoginUrl: loginURL, Params: &params}
	respData, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionMarshal, log.LogData("auth login url response"), nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(respData)
}

func (h ServicesApisHandler) authAuthorizeService(l *log.Log, r *http.Request) log.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionRead, log.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.AuthAuthorizeServiceRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionUnmarshal, log.LogData("auth authorize service request"), nil, err, http.StatusBadRequest, true)
	}

	scopes, err := scopeListFromDef(requestData.ApprovedScopes)
	if err != nil {
		return l.HttpResponseErrorData(log.StatusInvalid, "scopes", nil, err, http.StatusBadRequest, true)
	}

	//TODO: Fill "claims" with claims from access token
	token, tokenScopes, reg, err := h.coreAPIs.Auth.AuthorizeService(auth.TokenClaims{}, requestData.ServiceId, scopes, l)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionGet, "login url", nil, err, http.StatusInternalServerError, true)
	}

	scopesResp := scopeListToDef(tokenScopes)
	regResp := serviceRegToDef(reg)
	tokenType := Def.AuthAuthorizeServiceResponseTokenTypeBearer

	responseData := &Def.AuthAuthorizeServiceResponse{AccessToken: &token, TokenType: &tokenType, ApprovedScopes: &scopesResp, ServiceReg: regResp}
	respData, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionMarshal, log.LogData("auth authorize service response"), nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(respData)
}

func (h ServicesApisHandler) getServiceRegistrations(l *log.Log, r *http.Request) log.HttpResponse {
	serviceIDsParam := r.URL.Query().Get("ids")
	if serviceIDsParam == "" {
		return l.HttpResponseErrorData(log.StatusMissing, log.TypeQueryParam, log.StringArgs("ids"), nil, http.StatusBadRequest, false)
	}
	serviceIDs := strings.Split(serviceIDsParam, ",")

	serviceRegs, err := h.coreAPIs.Auth.GetServiceRegistrations(serviceIDs)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionGet, model.TypeServiceReg, nil, err, http.StatusInternalServerError, true)
	}

	serviceRegResp := serviceRegListToDef(serviceRegs)

	data, err := json.Marshal(serviceRegResp)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionMarshal, model.TypeServiceReg, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

//getCommonTest TODO get test
func (h ServicesApisHandler) getTest(l *log.Log, r *http.Request) log.HttpResponse {
	res := h.coreAPIs.Services.SerGetCommonTest(l)

	return l.HttpResponseSuccessMessage(res)
}

func (h ServicesApisHandler) createAnonymousProfile(l *log.Log, r *http.Request) log.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionRead, log.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.AnonymousProfile
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionUnmarshal, TypeAnonymousProfile, nil, err, http.StatusBadRequest, true)
	}

	_, err = h.coreAPIs.Services.CreateAnonymousProfile(l, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionGet, TypeAnonymousProfile, nil, err, http.StatusInternalServerError, true)
	}
	return l.HttpResponseSuccess()
}

func (h ServicesApisHandler) updateAnonymousProfile(l *log.Log, r *http.Request) log.HttpResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HttpResponseErrorData(log.StatusMissing, log.TypeQueryParam, log.StringArgs("id"), nil, http.StatusBadRequest, false)
	}
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionRead, log.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.AnonymousProfile
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionUnmarshal, log.LogData("invalid anonymous profile request"), nil, err, http.StatusBadRequest, true)
	}

	err = h.coreAPIs.Services.UpdateAnonymousProfile(l, requestData.Id, requestData.Favorites, requestData.Interests, requestData.LastModifiedDate, requestData.NegativeInterestTags, requestData.PositiveInterestTags, requestData.PrivacySettings, requestData.Over13)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionGet, TypeAnonymousProfile, nil, err, http.StatusInternalServerError, true)
	}
	return l.HttpResponseSuccess()
}

func (h ServicesApisHandler) getAnonymousProfile(l *log.Log, r *http.Request) log.HttpResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HttpResponseErrorData(log.StatusMissing, log.TypeQueryParam, log.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	profile, err := h.coreAPIs.Services.GetAnonymousProfile(l, ID)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionDelete, TypeAnonymousProfile, nil, err, http.StatusInternalServerError, true)
	}

	data, err := json.Marshal(profile)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionMarshal, TypeAnonymousProfile, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

func (h ServicesApisHandler) deleteAnonymousProfile(l *log.Log, r *http.Request) log.HttpResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HttpResponseErrorData(log.StatusMissing, log.TypeQueryParam, log.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	err := h.coreAPIs.Services.DeleteAnonymousProfile(l, ID)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionDelete, TypeAnonymousProfile, nil, err, http.StatusInternalServerError, true)
	}
	return l.HttpResponseSuccess()
}

//NewServicesApisHandler creates new rest services Handler instance
func NewServicesApisHandler(coreAPIs *core.APIs) ServicesApisHandler {
	return ServicesApisHandler{coreAPIs: coreAPIs}
}
