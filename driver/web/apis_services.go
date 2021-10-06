package web

import (
	"core-building-block/core"
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rokmetro/auth-library/tokenauth"
	"github.com/rokmetro/logging-library/logs"
	"github.com/rokmetro/logging-library/logutils"
)

//ServicesApisHandler handles the rest APIs implementation
type ServicesApisHandler struct {
	coreAPIs *core.APIs
}

func (h ServicesApisHandler) authLogin(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
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
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeCreds, nil, err, http.StatusBadRequest, true)
	}

	requestParams, err := interfaceToJSON(requestData.Params)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, "params", nil, err, http.StatusBadRequest, true)
	}

	anonymousID := ""
	if requestData.AnonymousId != nil {
		anonymousID = *requestData.AnonymousId
	}

	//preferences
	preferences := requestData.Preferences

	//profile ////
	requestProfile := requestData.Profile
	//generate ID
	profileIDUUID, _ := uuid.NewUUID()
	profileID := profileIDUUID.String()
	requestProfile.Id = &profileID
	profile := profileFromDef(requestProfile)
	//set date created
	profile.DateCreated = time.Now()

	message, accessToken, refreshToken, account, params, err := h.coreAPIs.Auth.Login(string(requestData.AuthType), requestCreds, requestData.AppTypeIdentifier, requestData.OrgId, requestParams, anonymousID, *profile, *preferences, l)
	if err != nil {
		return l.HttpResponseError("Error logging in", err, http.StatusInternalServerError, true)
	}

	if message != "" {
		responseData := &Def.ResLoginResponse{Message: &message}
		respData, err := json.Marshal(responseData)
		if err != nil {
			return l.HttpResponseErrorAction(logutils.ActionMarshal, logutils.MessageDataType("auth login response"), nil, err, http.StatusInternalServerError, false)
		}
		return l.HttpResponseSuccessJSON(respData)
	}

	tokenType := Def.ResSharedRokwireTokenTokenTypeBearer
	rokwireToken := Def.ResSharedRokwireToken{AccessToken: &accessToken, RefreshToken: &refreshToken, TokenType: &tokenType}

	var accountData *Def.ResLoginAccount
	if account != nil {
		///prepare response
		//profile
		profile := profileToDef(&account.Profile)
		//permissions
		permissions := applicationPermissionsToDef(account.Permissions)
		//roles
		roles := applicationRolesToDef(account.Roles)
		//groups
		groups := applicationGroupsToDef(account.Groups)
		//account auth types - we return only the one used for login
		authTypes := make([]Def.AccountAuthTypeFields, 1)
		for _, current := range account.AuthTypes {
			if current.AuthType.Code == string(requestData.AuthType) {
				authTypes[0] = accountAuthTypeToDef(current)
			}
		}
		accountData = &Def.ResLoginAccount{Id: account.ID, Permissions: &permissions, Roles: &roles, Groups: &groups, AuthTypes: &authTypes, Profile: profile}
	}

	responseData := &Def.ResLoginResponse{Token: &rokwireToken, Account: accountData, Params: &params}
	respData, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, logutils.MessageDataType("auth login response"), nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(respData)
}

func (h ServicesApisHandler) authRefresh(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
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

func (h ServicesApisHandler) authLoginURL(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ReqLoginUrlRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, "auth login url request", nil, err, http.StatusBadRequest, true)
	}

	loginURL, params, err := h.coreAPIs.Auth.GetLoginURL(string(requestData.AuthType), requestData.AppTypeIdentifier, requestData.OrgId, requestData.RedirectUri, l)
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

func (h ServicesApisHandler) authAuthorizeService(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
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
	token, tokenScopes, reg, err := h.coreAPIs.Auth.AuthorizeService(tokenauth.Claims{}, requestData.ServiceId, scopes, l)
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

func (h ServicesApisHandler) getServiceRegistrations(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
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

func (h ServicesApisHandler) deleteAccount(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	err := h.coreAPIs.Services.SerDeleteAccount(claims.Subject)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionDelete, model.TypeAccount, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h ServicesApisHandler) getProfile(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	profile, err := h.coreAPIs.Services.SerGetProfile(claims.Subject)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeProfile, nil, err, http.StatusInternalServerError, true)
	}

	profileResp := profileToDef(profile)

	data, err := json.Marshal(profileResp)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeProfile, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

func (h ServicesApisHandler) updateProfile(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ProfileFields
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, "profile update request", nil, err, http.StatusBadRequest, true)
	}

	profile := profileFromDef(&requestData)

	err = h.coreAPIs.Services.SerUpdateProfile(claims.Subject, profile)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypeProfile, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h ServicesApisHandler) updateAccountPreferences(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var preferences map[string]interface{}
	err = json.Unmarshal(data, &preferences)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, "account preferences update request", nil, err, http.StatusBadRequest, true)
	}

	err = h.coreAPIs.Services.SerUpdateAccountPreferences(claims.Subject, preferences)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypeAccountPreferences, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h ServicesApisHandler) getPreferences(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	preferences, _, err := h.coreAPIs.Services.SerGetPreferences(claims.Subject)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeProfile, nil, err, http.StatusInternalServerError, true)
	}

	response := preferencesToDef(preferences)

	data, err := json.Marshal(response)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeAccount, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

//getCommonTest TODO get test
func (h ServicesApisHandler) getTest(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	res := h.coreAPIs.Services.SerGetCommonTest(l)

	return l.HttpResponseSuccessMessage(res)
}

//Handler for verify endpoint
func (h ServicesApisHandler) verifyCode(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	id := r.URL.Query().Get("id")
	if id == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("code"), nil, http.StatusBadRequest, false)
	}

	if err := h.coreAPIs.Auth.Verify(id, code, l); err != nil {
		return l.HttpResponseErrorAction(logutils.ActionValidate, "code", nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessMessage("Code verified!")
}

//NewServicesApisHandler creates new rest services Handler instance
func NewServicesApisHandler(coreAPIs *core.APIs) ServicesApisHandler {
	return ServicesApisHandler{coreAPIs: coreAPIs}
}
