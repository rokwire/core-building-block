package web

import (
	"core-building-block/core"
	Def "core-building-block/driver/web/docs/gen"
	"encoding/json"
	"io/ioutil"
	"net/http"

	log "github.com/rokmetro/logging-library/loglib"
)

//ServicesApisHandler handles the rest APIs implementation
type ServicesApisHandler struct {
	coreAPIs *core.APIs
}

//getAuthTest TODO get test
func (h ServicesApisHandler) getAuthTest(l *log.Log, r *http.Request) log.HttpResponse {
	res := h.coreAPIs.Services.SerGetAuthTest(l)

	return l.HttpResponseSuccessMessage(res)
}

func (h ServicesApisHandler) authLogin(l *log.Log, r *http.Request) log.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionRead, log.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	typeLoginRequest := log.LogData("auth login request")

	var requestData Def.AuthLoginRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionUnmarshal, typeLoginRequest, nil, err, http.StatusBadRequest, true)
	}

	requestCreds, err := mapInterfaceToJSON(requestData.Creds)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionMarshal, "creds", nil, err, http.StatusBadRequest, true)
	}

	requestParams, err := mapInterfaceToJSON(requestData.Params)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionMarshal, "params", nil, err, http.StatusBadRequest, true)
	}

	accessToken, refreshToken, user, params, err := h.coreAPIs.Auth.Login(string(requestData.AuthType), requestCreds, requestData.OrgId, requestData.AppId, requestParams, l)
	if err != nil {
		return l.HttpResponseError("Error logging in", err, http.StatusInternalServerError, true)
	}

	responseData := &Def.AuthLoginResponse{AccessToken: &accessToken, User: userToDef(user), Params: &params, RefreshToken: &refreshToken}
	respData, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionMarshal, typeLoginRequest, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(respData)
}

//getCommonTest TODO get test
func (h ServicesApisHandler) getCommonTest(l *log.Log, r *http.Request) log.HttpResponse {
	res := h.coreAPIs.Services.SerGetCommonTest(l)

	return l.HttpResponseSuccessMessage(res)
}

//NewServicesApisHandler creates new rest services Handler instance
func NewServicesApisHandler(coreAPIs *core.APIs) ServicesApisHandler {
	return ServicesApisHandler{coreAPIs: coreAPIs}
}
