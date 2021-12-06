package web

import (
	"core-building-block/core"
	"core-building-block/core/model"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/rokwire/core-auth-library-go/tokenauth"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

//BBsApisHandler handles the APIs implementation used by the platform building blocks
type BBsApisHandler struct {
	coreAPIs *core.APIs
}

//getTest TODO get test
func (h BBsApisHandler) getTest(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	res := h.coreAPIs.BBs.BBsGetTest()

	return l.HttpResponseSuccessMessage(res)
}

func (h BBsApisHandler) getServiceRegistrations(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	serviceIDsParam := r.URL.Query().Get("ids")
	if serviceIDsParam == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("ids"), nil, http.StatusBadRequest, false)
	}
	serviceIDs := strings.Split(serviceIDsParam, ",")

	serviceRegs, err := h.coreAPIs.Auth.GetServiceRegistrations(serviceIDs)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeServiceReg, nil, err, http.StatusInternalServerError, true)
	}

	serviceRegResp := authServiceRegListToDef(serviceRegs)

	data, err := json.Marshal(serviceRegResp)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeServiceReg, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

func (h BBsApisHandler) getDeletedAccounts(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	accountIDs, err := h.coreAPIs.BBs.BBsGetDeletedAccounts()
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, "deleted account ids", nil, err, http.StatusInternalServerError, true)
	}

	data, err := json.Marshal(accountIDs)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, "deleted account ids", nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

//NewBBsApisHandler creates new bbs Handler instance
func NewBBsApisHandler(coreAPIs *core.APIs) BBsApisHandler {
	return BBsApisHandler{coreAPIs: coreAPIs}
}
