package web

import (
	"core-building-block/core"
	"core-building-block/core/model"
	"encoding/json"
	"io/ioutil"
	"net/http"

	log "github.com/rokmetro/logging-library/loglib"
	"gopkg.in/go-playground/validator.v9"
)

//ServicesApisHandler handles the rest APIs implementation
type ServicesApisHandler struct {
	coreAPIs *core.APIs
}

//GetAuthTest TODO get test
func (h ServicesApisHandler) GetAuthTest(l *log.Log, w http.ResponseWriter, r *http.Request) {
	res := h.coreAPIs.Services.SerGetAuthTest(l)
	w.Write([]byte(res))
}

type authLoginRequest struct {
	AuthType string `json:"auth_type" validate:"required"`
	Creds    string `json:"creds" validate:"required"`
	OrgID    string `json:"org_id" validate:"required"`
	AppID    string `json:"app_id" validate:"required"`
	Params   string `json:"params"`
}

type authLoginResponse struct {
	AccessToken  string      `json:"access_token"`
	User         *model.User `json:"user"`
	RefreshToken string      `json:"refresh_token"`
}

//AuthLogin authenticates a user and returns the necessary credentials and user information
func (h ServicesApisHandler) AuthLogin(l *log.Log, w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		l.RequestErrorAction(w, log.ActionRead, log.TypeRequestBody, nil, err, http.StatusBadRequest, false)
		return
	}

	typeLoginRequest := log.LogData("auth login request")

	var requestData authLoginRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		l.RequestErrorAction(w, log.ActionUnmarshal, typeLoginRequest, nil, err, http.StatusBadRequest, true)
		return
	}

	//validate
	validate := validator.New()
	err = validate.Struct(requestData)
	if err != nil {
		l.RequestErrorAction(w, log.ActionValidate, typeLoginRequest, nil, err, http.StatusBadRequest, true)
		return
	}

	accessToken, user, refreshToken, err := h.coreAPIs.Auth.Login(requestData.AuthType, requestData.Creds, requestData.OrgID, requestData.AppID, requestData.Params, l)
	if err != nil {
		l.RequestError(w, "Error logging in", err, http.StatusInternalServerError, true)
		return
	}

	responseData := &authLoginResponse{AccessToken: accessToken, User: user, RefreshToken: refreshToken}
	respData, err := json.Marshal(responseData)
	if err != nil {
		l.RequestErrorAction(w, log.ActionMarshal, typeLoginRequest, nil, err, http.StatusInternalServerError, false)
		return
	}

	l.RequestSuccessJSON(w, respData)
}

//GetCommonTest TODO get test
func (h ServicesApisHandler) GetCommonTest(l *log.Log, w http.ResponseWriter, r *http.Request) {
	res := h.coreAPIs.Services.SerGetCommonTest(l)
	w.Write([]byte(res))
}

//SerVersion gives the service version
func (h ServicesApisHandler) SerVersion(l *log.Log, w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(h.coreAPIs.Services.SerGetVersion(l)))
}

//NewServicesApisHandler creates new rest services Handler instance
func NewServicesApisHandler(coreAPIs *core.APIs) ServicesApisHandler {
	return ServicesApisHandler{coreAPIs: coreAPIs}
}
