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

	"github.com/rokwire/core-auth-library-go/tokenauth"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
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

	ip := utils.GetIP(l, r)
	if err != nil {
		return l.HttpResponseError("Error getting IP", err, http.StatusInternalServerError, true)
	}

	var requestData Def.ReqSharedLogin
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("auth login request"), nil, err, http.StatusBadRequest, true)
	}

	//creds
	requestCreds, err := interfaceToJSON(requestData.Creds)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeCreds, nil, err, http.StatusBadRequest, true)
	}

	//params
	requestParams, err := interfaceToJSON(requestData.Params)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, "params", nil, err, http.StatusBadRequest, true)
	}

	//preferences
	var requestPreferences map[string]interface{}
	if requestData.Preferences != nil {
		requestPreferences = *requestData.Preferences
	}

	//profile ////
	requestProfile := profileFromDefNullable(requestData.Profile)

	//device
	requestDevice := requestData.Device

	message, loginSession, mfaTypes, err := h.coreAPIs.Auth.Login(ip, string(requestDevice.Type), requestDevice.Os, *requestDevice.DeviceId,
		string(requestData.AuthType), requestCreds, requestData.ApiKey, requestData.AppTypeIdentifier, requestData.OrgId, requestParams, requestProfile, requestPreferences, l)
	if err != nil {
		return l.HttpResponseError("Error logging in", err, http.StatusInternalServerError, true)
	}

	///prepare response

	//message
	if message != nil {
		responseData := &Def.ResSharedLogin{Message: message}
		respData, err := json.Marshal(responseData)
		if err != nil {
			return l.HttpResponseErrorAction(logutils.ActionMarshal, logutils.MessageDataType("auth login response"), nil, err, http.StatusInternalServerError, false)
		}
		return l.HttpResponseSuccessJSON(respData)
	}

	if loginSession.State != "" {
		//params
		var paramsRes interface{}
		if loginSession.Params != nil {
			paramsRes = loginSession.Params
		}

		mfaResp := mfaDataListToDef(mfaTypes)
		responseData := &Def.ResSharedLoginMfa{AccountId: loginSession.Identifier, Enrolled: mfaResp, Params: &paramsRes,
			SessionId: loginSession.ID, State: loginSession.State}
		respData, err := json.Marshal(responseData)
		if err != nil {
			return l.HttpResponseErrorAction(logutils.ActionMarshal, logutils.MessageDataType("auth login response"), nil, err, http.StatusInternalServerError, false)
		}
		return l.HttpResponseSuccessJSON(respData)
	}

	return authBuildLoginResponse(l, loginSession)
}

func (h ServicesApisHandler) authLoginMFA(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var mfaData Def.ReqSharedLoginMfa
	err = json.Unmarshal(data, &mfaData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("login mfa request"), nil, err, http.StatusBadRequest, true)
	}

	message, loginSession, err := h.coreAPIs.Auth.LoginMFA(mfaData.ApiKey, mfaData.AccountId, mfaData.SessionId, mfaData.Identifier, string(mfaData.Type), mfaData.Code, mfaData.State, l)
	if message != nil {
		return l.HttpResponseError(*message, err, http.StatusUnauthorized, false)
	}
	if err != nil {
		return l.HttpResponseError("Error logging in", err, http.StatusInternalServerError, true)
	}

	return authBuildLoginResponse(l, loginSession)
}

func (h ServicesApisHandler) accountExists(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ReqAccountExistsRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, logutils.TypeRequest, nil, err, http.StatusBadRequest, true)
	}

	accountExists, err := h.coreAPIs.Auth.AccountExists(string(requestData.AuthType), requestData.UserIdentifier, requestData.ApiKey, requestData.AppTypeIdentifier, requestData.OrgId, l)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, logutils.MessageDataType("account exists"), nil, err, http.StatusInternalServerError, false)
	}

	respData, err := json.Marshal(accountExists)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, logutils.TypeResponse, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(respData)
}

func (h ServicesApisHandler) authRefresh(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ReqSharedRefresh
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("auth refresh request"), nil, err, http.StatusBadRequest, true)
	}

	loginSession, err := h.coreAPIs.Auth.Refresh(requestData.RefreshToken, requestData.ApiKey, l)
	if err != nil {
		return l.HttpResponseError("Error refreshing token", err, http.StatusInternalServerError, true)
	}
	if loginSession == nil {
		//if login session is null then unauthorized
		l.Infof("trying to refresh - %s", requestData.RefreshToken)
		return l.HttpResponseError(http.StatusText(http.StatusUnauthorized), nil, http.StatusUnauthorized, true)
	}

	accessToken := loginSession.AccessToken
	refreshToken := loginSession.CurrentRefreshToken()
	var paramsRes interface{}
	if loginSession.Params != nil {
		paramsRes = loginSession.Params
	}

	tokenType := Def.ResSharedRokwireTokenTokenTypeBearer
	rokwireToken := Def.ResSharedRokwireToken{AccessToken: &accessToken, RefreshToken: &refreshToken, TokenType: &tokenType}
	responseData := &Def.ResSharedRefresh{Token: &rokwireToken, Params: &paramsRes}
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

	var requestData Def.ReqSharedLoginUrl
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, "auth login url request", nil, err, http.StatusBadRequest, true)
	}

	loginURL, params, err := h.coreAPIs.Auth.GetLoginURL(string(requestData.AuthType), requestData.AppTypeIdentifier, requestData.OrgId, requestData.RedirectUri, requestData.ApiKey, l)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, "login url", nil, err, http.StatusInternalServerError, true)
	}

	responseData := &Def.ResSharedLoginUrl{LoginUrl: loginURL, Params: &params}
	respData, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, "auth login url response", nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(respData)
}

func (h ServicesApisHandler) linkAccountAuthType(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ReqAccountAuthTypeLinkRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("account auth type link request"), nil, err, http.StatusBadRequest, true)
	}

	//creds
	requestCreds, err := interfaceToJSON(requestData.Creds)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeCreds, nil, err, http.StatusBadRequest, true)
	}

	//params
	requestParams, err := interfaceToJSON(requestData.Params)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, "params", nil, err, http.StatusBadRequest, true)
	}

	message, err := h.coreAPIs.Auth.LinkAccountAuthType(claims.Subject, string(requestData.AuthType), requestData.AppTypeIdentifier, requestCreds, requestParams, l)
	if err != nil {
		return l.HttpResponseError("Error logging in", err, http.StatusInternalServerError, true)
	}

	if message != nil {
		return l.HttpResponseSuccessMessage(*message)
	}

	return l.HttpResponseSuccess()
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

func (h ServicesApisHandler) getAccount(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	account, err := h.coreAPIs.Services.SerGetAccount(claims.Subject)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeAccount, nil, err, http.StatusInternalServerError, true)
	}

	var accountData *Def.ResSharedAccount
	if account != nil {
		accountData = accountToDef(*account)
	}

	data, err := json.Marshal(accountData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeAccount, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

func (h ServicesApisHandler) getMFATypes(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	mfaDataList, err := h.coreAPIs.Auth.GetMFATypes(claims.Subject)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeMFAType, nil, err, http.StatusInternalServerError, true)
	}

	mfaResp := mfaDataListToDef(mfaDataList)

	data, err := json.Marshal(mfaResp)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeMFAType, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

func (h ServicesApisHandler) addMFAType(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var mfaData Def.ReqSharedMfa
	err = json.Unmarshal(data, &mfaData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("add mfa request"), nil, err, http.StatusBadRequest, true)
	}

	mfa, err := h.coreAPIs.Auth.AddMFAType(claims.Subject, mfaData.Identifier, string(mfaData.Type))
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionInsert, model.TypeMFAType, nil, err, http.StatusInternalServerError, true)
	}

	mfaResp := mfaDataToDef(mfa)

	respData, err := json.Marshal(mfaResp)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeMFAType, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(respData)
}

func (h ServicesApisHandler) removeMFAType(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var mfaData Def.ReqSharedMfa
	err = json.Unmarshal(data, &mfaData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("remove mfa request"), nil, err, http.StatusBadRequest, true)
	}

	err = h.coreAPIs.Auth.RemoveMFAType(claims.Subject, mfaData.Identifier, string(mfaData.Type))
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionDelete, model.TypeMFAType, nil, err, http.StatusInternalServerError, true)
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

	var requestData Def.ReqSharedProfile
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, "profile update request", nil, err, http.StatusBadRequest, true)
	}

	profile := profileFromDef(&requestData)

	err = h.coreAPIs.Services.SerUpdateProfile(claims.Subject, &profile)
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
	preferences, err := h.coreAPIs.Services.SerGetPreferences(claims.Subject)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeProfile, nil, err, http.StatusInternalServerError, true)
	}

	response := preferences

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
func (h ServicesApisHandler) verifyCredential(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	id := r.URL.Query().Get("id")
	if id == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("code"), nil, http.StatusBadRequest, false)
	}

	if err := h.coreAPIs.Auth.VerifyCredential(id, code, l); err != nil {
		return l.HttpResponseErrorAction(logutils.ActionValidate, "code", nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessMessage("Code verified!")
}

//Handler for reset password endpoint from client application
func (h ServicesApisHandler) updateCredential(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	accountID := claims.Subject
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ReqCredentialUpdateRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("auth reset password client request"), nil, err, http.StatusBadRequest, true)
	}

	//params
	requestParams, err := interfaceToJSON(requestData.Params)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, "params", nil, err, http.StatusBadRequest, true)
	}

	if err := h.coreAPIs.Auth.UpdateCredential(accountID, requestData.AccountAuthTypeId, requestParams, l); err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, "password", nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessMessage("Reset Password from client successfully")
}

//Handler for reset password endpoint from reset link
func (h ServicesApisHandler) forgotCredentialComplete(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ReqCredentialForgotCompleteRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("auth reset password link request"), nil, err, http.StatusBadRequest, true)
	}

	//params
	requestParams, err := interfaceToJSON(requestData.Params)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, "params", nil, err, http.StatusBadRequest, true)
	}

	if err := h.coreAPIs.Auth.ResetForgotCredential(requestData.CredentialId, requestData.ResetCode, requestParams, l); err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, "password", nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessMessage("Reset Password from link successfully")
}

//Handler for forgot credential endpoint
func (h ServicesApisHandler) forgotCredentialInitiate(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ReqCredentialForgotInitiateRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("auth reset password request"), nil, err, http.StatusBadRequest, true)
	}

	if err := h.coreAPIs.Auth.ForgotCredential(string(requestData.AuthType), requestData.AppTypeIdentifier,
		requestData.OrgId, requestData.ApiKey, requestData.Identifier, l); err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, "password", nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessMessage("Sent forgot password link successfully")
}

//Handler for resending verify code
func (h ServicesApisHandler) sendVerifyCredential(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ReqCredentialSendVerifyRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("auth resend verify code request"), nil, err, http.StatusBadRequest, true)
	}

	if err := h.coreAPIs.Auth.SendVerifyCredential(string(requestData.AuthType), requestData.AppTypeIdentifier, requestData.OrgId, requestData.ApiKey, requestData.Identifier, l); err != nil {
		return l.HttpResponseErrorAction(logutils.ActionSend, "code", nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessMessage("Verification code sent")
}

func (h ServicesApisHandler) verifyMFA(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var mfaData Def.ReqSharedMfa
	err = json.Unmarshal(data, &mfaData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("verify mfa request"), nil, err, http.StatusBadRequest, true)
	}

	if mfaData.Code == nil || *mfaData.Code == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, "mfa code", nil, nil, http.StatusBadRequest, true)
	}

	message, recoveryCodes, err := h.coreAPIs.Auth.VerifyMFA(claims.Subject, mfaData.Identifier, string(mfaData.Type), *mfaData.Code)
	if message != nil {
		return l.HttpResponseError(*message, nil, http.StatusBadRequest, true)
	}
	if err != nil {
		return l.HttpResponseError("Error verifying MFA", err, http.StatusInternalServerError, true)
	}

	if recoveryCodes == nil {
		recoveryCodes = []string{}
	}

	response, err := json.Marshal(recoveryCodes)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, "mfa recovery codes", nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(response)
}

//NewServicesApisHandler creates new rest services Handler instance
func NewServicesApisHandler(coreAPIs *core.APIs) ServicesApisHandler {
	return ServicesApisHandler{coreAPIs: coreAPIs}
}
