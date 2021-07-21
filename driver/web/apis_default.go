package web

import (
	"core-building-block/core"
	"core-building-block/core/model"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	log "github.com/rokmetro/logging-library/loglib"
)

//DefaultApisHandler handles default APIs implementation - version etc
type DefaultApisHandler struct {
	coreAPIs *core.APIs
}

//getVersion gives the service version
func (h DefaultApisHandler) getVersion(l *log.Log, w http.ResponseWriter, r *http.Request) log.HttpResponse {
	version := h.coreAPIs.GetVersion()

	return l.HttpResponseSuccessMessage(version)
}

func (h DefaultApisHandler) getServiceRegistrations(l *log.Log, w http.ResponseWriter, r *http.Request) log.HttpResponse {
	params := mux.Vars(r)
	serviceIDsParam := params["ids"]
	if len(serviceIDsParam) <= 0 {
		return l.HttpResponseErrorData(log.StatusMissing, log.TypeQueryParam, log.StringArgs("ids"), nil, http.StatusBadRequest, false)
	}
	serviceIDs := strings.Split(serviceIDsParam, ",")

	serviceRegs, err := h.coreAPIs.Auth.GetServiceRegistrations(serviceIDs)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionGet, model.TypeServiceReg, nil, err, http.StatusInternalServerError, true)
	}

	data, err := json.Marshal(serviceRegs)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionMarshal, model.TypeServiceReg, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

//NewDefaultApisHandler creates new rest services Handler instance
func NewDefaultApisHandler(coreAPIs *core.APIs) DefaultApisHandler {
	return DefaultApisHandler{coreAPIs: coreAPIs}
}
