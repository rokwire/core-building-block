package web

import (
	"core-building-block/core"
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
	"core-building-block/utils"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/rokwire/core-auth-library-go/tokenauth"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

const (
	actionGrant logutils.MessageActionType = "granting"
)

//AdminApisHandler handles the admin rest APIs implementation
type AdminApisHandler struct {
	coreAPIs *core.APIs
}

//getTest TODO get test
func (h AdminApisHandler) getTest(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	res := h.coreAPIs.Administration.AdmGetTest()

	return l.HttpResponseSuccessMessage(res)
}

//getTestModel gives a test model instance
func (h AdminApisHandler) getTestModel(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	res := h.coreAPIs.Administration.AdmGetTestModel()

	return l.HttpResponseSuccessMessage(res)
}

func (h AdminApisHandler) adminLogin(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	//get ip
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

	return authBuildLoginResponse(l, loginSession)
}

func (h AdminApisHandler) adminLoginMFA(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
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

func (h AdminApisHandler) adminLoginURL(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
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

func (h AdminApisHandler) adminRefresh(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
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

func (h AdminApisHandler) getMFATypes(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
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

func (h AdminApisHandler) addMFAType(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
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

func (h AdminApisHandler) removeMFAType(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
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

func (h AdminApisHandler) adminVerifyMFA(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
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

//NewAdminApisHandler creates new admin rest Handler instance
func NewAdminApisHandler(coreAPIs *core.APIs) AdminApisHandler {
	return AdminApisHandler{coreAPIs: coreAPIs}
}
