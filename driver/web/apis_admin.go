package web

import (
	"core-building-block/core"
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"gopkg.in/go-playground/validator.v9"

	"github.com/gorilla/mux"
	log "github.com/rokmetro/logging-library/loglib"
)

//AdminApisHandler handles the admin rest APIs implementation
type AdminApisHandler struct {
	coreAPIs *core.APIs
}

//getTest TODO get test
func (h AdminApisHandler) getTest(l *log.Log, r *http.Request) log.HttpResponse {
	res := h.coreAPIs.Administration.AdmGetTest()

	return l.HttpResponseSuccessMessage(res)
}

//getTestModel gives a test model instance
func (h AdminApisHandler) getTestModel(l *log.Log, r *http.Request) log.HttpResponse {
	res := h.coreAPIs.Administration.AdmGetTestModel()

	return l.HttpResponseSuccessMessage(res)
}

//createGlobalConfig creates a global config
func (h AdminApisHandler) createGlobalConfig(l *log.Log, r *http.Request) log.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionRead, log.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.GlobalConfig
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionUnmarshal, model.TypeGlobalConfig, nil, err, http.StatusBadRequest, true)
	}

	//validate
	validate := validator.New()
	err = validate.Struct(requestData)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionValidate, model.TypeGlobalConfig, nil, err, http.StatusBadRequest, true)
	}

	_, err = h.coreAPIs.Administration.AdmCreateGlobalConfig(requestData.Setting)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionCreate, model.TypeGlobalConfig, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//getGlobalConfig gets config
func (h AdminApisHandler) getGlobalConfig(l *log.Log, r *http.Request) log.HttpResponse {
	config, err := h.coreAPIs.Administration.AdmGetGlobalConfig()
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionGet, model.TypeGlobalConfig, nil, err, http.StatusInternalServerError, true)
	}

	var responseData *Def.GlobalConfig
	if config != nil {
		responseData = &Def.GlobalConfig{Setting: config.Setting}
	}
	data, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionMarshal, model.TypeGlobalConfig, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

//updateGlobalConfig updates global config
func (h AdminApisHandler) updateGlobalConfig(l *log.Log, r *http.Request) log.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionRead, log.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var updateConfig Def.GlobalConfig
	err = json.Unmarshal(data, &updateConfig)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionUnmarshal, model.TypeGlobalConfig, nil, err, http.StatusBadRequest, true)
	}

	//validate
	validate := validator.New()
	err = validate.Struct(updateConfig)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionValidate, model.TypeGlobalConfig, nil, err, http.StatusBadRequest, true)
	}
	setting := updateConfig.Setting

	err = h.coreAPIs.Administration.AdmUpdateGlobalConfig(setting)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionUpdate, model.TypeGlobalConfig, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//createOrganization creates organization
func (h AdminApisHandler) createOrganization(l *log.Log, r *http.Request) log.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionRead, log.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}
	var requestData Def.Organization
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionUnmarshal, model.TypeOrganization, nil, err, http.StatusBadRequest, true)
	}

	//validate
	validate := validator.New()
	err = validate.Struct(requestData)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionValidate, model.TypeOrganization, nil, err, http.StatusBadRequest, true)
	}

	name := requestData.Name
	requestType := requestData.Type
	requiresOwnLogin := requestData.RequiresOwnLogin
	loginTypes := requestData.LoginTypes
	organizationDomains := requestData.Config.Domains

	_, err = h.coreAPIs.Administration.AdmCreateOrganization(name, string(requestType), *requiresOwnLogin, *loginTypes, *organizationDomains)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionCreate, model.TypeOrganization, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//updateOrganization updates organization
func (h AdminApisHandler) updateOrganization(l *log.Log, r *http.Request) log.HttpResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HttpResponseErrorData(log.StatusMissing, log.TypeQueryParam, log.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorData(log.StatusInvalid, log.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}
	var requestData Def.Organization
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionUnmarshal, model.TypeOrganization, nil, err, http.StatusBadRequest, true)
	}

	//validate
	validate := validator.New()
	err = validate.Struct(requestData)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionValidate, model.TypeOrganization, nil, err, http.StatusBadRequest, true)
	}

	name := requestData.Name
	requestType := requestData.Type
	requiresOwnLogin := requestData.RequiresOwnLogin
	loginTypes := requestData.LoginTypes
	organizationDomains := requestData.Config.Domains

	err = h.coreAPIs.Administration.AdmUpdateOrganization(ID, name, string(requestType), *requiresOwnLogin, *loginTypes, *organizationDomains)
	if err != nil {
		return l.HttpResponseErrorAction(log.ActionUpdate, model.TypeOrganization, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//NewAdminApisHandler creates new admin rest Handler instance
func NewAdminApisHandler(coreAPIs *core.APIs) AdminApisHandler {
	return AdminApisHandler{coreAPIs: coreAPIs}
}
