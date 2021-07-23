package web

import (
	"core-building-block/core"
	"core-building-block/core/model"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	log "github.com/rokmetro/logging-library/loglib"
	"gopkg.in/go-playground/validator.v9"
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

func (h ServicesApisHandler) getAuthServiceRegistrations(l *log.Log, r *http.Request) log.HttpResponse {
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

type authLoginRequest struct {
	AuthType string `json:"auth_type" validate:"required"`
	Creds    string `json:"creds" validate:"required"`
	OrgID    string `json:"org_id" validate:"required"`
	AppID    string `json:"app_id" validate:"required"`
	Params   string `json:"params"`
}

type authLoginResponse struct {
	AccessToken  string                 `json:"access_token"`
	User         *model.User            `json:"user"`
	Params       map[string]interface{} `json:"params"`
	RefreshToken string                 `json:"refresh_token"`
}

func (h ServicesApisHandler) authLogin(l *log.Log, r *http.Request) log.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionRead, log.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	typeLoginRequest := log.LogData("auth login request")

	var requestData authLoginRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionUnmarshal, typeLoginRequest, nil, err, http.StatusBadRequest, true)
	}

	//validate
	validate := validator.New()
	err = validate.Struct(requestData)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionValidate, typeLoginRequest, nil, err, http.StatusBadRequest, true)
	}

	accessToken, refreshToken, user, params, err := h.coreAPIs.Auth.Login(requestData.AuthType, requestData.Creds, requestData.OrgID, requestData.AppID, requestData.Params, l)
	if err != nil {
		return l.HttpResponseError("Error logging in", err, http.StatusInternalServerError, true)
	}

	responseData := &authLoginResponse{AccessToken: accessToken, User: user, Params: params, RefreshToken: refreshToken}
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
