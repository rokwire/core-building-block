package web

import (
	"core-building-block/core"
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/rokwire/core-auth-library-go/tokenauth"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

//TPSApisHandler handles the APIs implementation used by third-party services
type TPSApisHandler struct {
	coreAPIs *core.APIs
}

func (h TPSApisHandler) getServiceRegistrations(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
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

func (h TPSApisHandler) getAuthKeys(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	keys, err := h.coreAPIs.Auth.GetAuthKeySet()
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeJSONWebKeySet, logutils.StringArgs("auth"), err, http.StatusInternalServerError, true)
	}

	keysResp := jsonWebKeySetDef(keys)

	data, err := json.Marshal(keysResp)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeJSONWebKeySet, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

func (h TPSApisHandler) getServiceAccessToken(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.AccessTokenRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("service account access token request"), nil, err, http.StatusBadRequest, true)
	}

	//creds
	requestCreds, err := interfaceToJSON(requestData.Creds)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeCreds, nil, err, http.StatusBadRequest, true)
	}

	message, accessToken, err := h.coreAPIs.Auth.GetServiceAccessToken(string(requestData.AuthType), requestCreds, l)
	if err != nil {
		if message != nil {
			return l.HttpResponseError(*message, err, http.StatusUnauthorized, false)
		}
		return l.HttpResponseError("Error getting access token", err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccessMessage(accessToken)
}

func (h TPSApisHandler) addServiceToken(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	token, err := h.coreAPIs.Auth.AddServiceToken(claims.Subject, l)
	if err != nil {
		return l.HttpResponseError("Error adding service account token", err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccessMessage(token)
}

func (h TPSApisHandler) removeServiceToken(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.StaticToken
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, logutils.MessageDataType("service account static token"), nil, err, http.StatusBadRequest, true)
	}

	err = h.coreAPIs.Auth.RemoveServiceToken(claims.Subject, requestData.Token)
	if err != nil {
		return l.HttpResponseError("Error removing service account token", err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//NewTPSApisHandler creates new tps Handler instance
func NewTPSApisHandler(coreAPIs *core.APIs) TPSApisHandler {
	return TPSApisHandler{coreAPIs: coreAPIs}
}
