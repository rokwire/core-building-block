package web

import (
	"core-building-block/core"
	"net/http"

	"github.com/gorilla/mux"
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

//getCommonTest TODO get test
func (h ServicesApisHandler) getCommonTest(l *log.Log, r *http.Request) log.HttpResponse {
	res := h.coreAPIs.Services.SerGetCommonTest(l)

	return l.HttpResponseSuccessMessage(res)
}

//Handler for verify endpoint
func (h ServicesApisHandler) verifyCode(l *log.Log, r *http.Request) log.HttpResponse {
	params := mux.Vars(r)
	authType, email, code := params["auth-type"], params["id"], params["code"]
	if authType == "" || email == "" || code == "" {
		return l.HttpResponseError(string(log.StatusMissing), nil, http.StatusBadRequest, false)

	}

	if err := h.coreAPIs.Auth.Verify(authType, email, code, l); err != nil {
		return l.HttpResponseError("", err, http.StatusInternalServerError, false)

	}
	return l.HttpResponseSuccessMessage("code verified")
}

//NewServicesApisHandler creates new rest services Handler instance
func NewServicesApisHandler(coreAPIs *core.APIs) ServicesApisHandler {
	return ServicesApisHandler{coreAPIs: coreAPIs}
}
