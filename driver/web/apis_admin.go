package web

import (
	"core-building-block/core"
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/rokmetro/logging-library/logs"
	"github.com/rokmetro/logging-library/logutils"
)

//AdminApisHandler handles the admin rest APIs implementation
type AdminApisHandler struct {
	coreAPIs *core.APIs
}

//getTest TODO get test
func (h AdminApisHandler) getTest(l *logs.Log, r *http.Request) logs.HttpResponse {
	res := h.coreAPIs.Administration.AdmGetTest()

	return l.HttpResponseSuccessMessage(res)
}

//getTestModel gives a test model instance
func (h AdminApisHandler) getTestModel(l *logs.Log, r *http.Request) logs.HttpResponse {
	res := h.coreAPIs.Administration.AdmGetTestModel()

	return l.HttpResponseSuccessMessage(res)
}

//createGlobalConfig creates a global config
func (h AdminApisHandler) createGlobalConfig(l *logs.Log, r *http.Request) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.GlobalConfig
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeGlobalConfig, nil, err, http.StatusBadRequest, true)
	}

	_, err = h.coreAPIs.Administration.AdmCreateGlobalConfig(requestData.Setting)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionCreate, model.TypeGlobalConfig, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//getGlobalConfig gets config
func (h AdminApisHandler) getGlobalConfig(l *logs.Log, r *http.Request) logs.HttpResponse {
	config, err := h.coreAPIs.Administration.AdmGetGlobalConfig()
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeGlobalConfig, nil, err, http.StatusInternalServerError, true)
	}

	var responseData *Def.GlobalConfig
	if config != nil {
		responseData = &Def.GlobalConfig{Setting: config.Setting}
	}
	data, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeGlobalConfig, nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

//updateGlobalConfig updates global config
func (h AdminApisHandler) updateGlobalConfig(l *logs.Log, r *http.Request) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var updateConfig Def.GlobalConfig
	err = json.Unmarshal(data, &updateConfig)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeGlobalConfig, nil, err, http.StatusBadRequest, true)
	}

	setting := updateConfig.Setting

	err = h.coreAPIs.Administration.AdmUpdateGlobalConfig(setting)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypeGlobalConfig, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//createOrganization creates organization
func (h AdminApisHandler) createOrganization(l *logs.Log, r *http.Request) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}
	var requestData Def.Organization
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeOrganization, nil, err, http.StatusBadRequest, true)
	}

	name := requestData.Name
	requestType := requestData.Type
	requiresOwnLogin := requestData.RequiresOwnLogin
	loginTypes := requestData.LoginTypes
	organizationDomains := requestData.Config.Domains

	_, err = h.coreAPIs.Administration.AdmCreateOrganization(name, string(requestType), *requiresOwnLogin, *loginTypes, *organizationDomains)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionCreate, model.TypeOrganization, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//updateOrganization updates organization
func (h AdminApisHandler) updateOrganization(l *logs.Log, r *http.Request) logs.HttpResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorData(logutils.StatusInvalid, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}
	var requestData Def.Organization
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeOrganization, nil, err, http.StatusBadRequest, true)
	}

	name := requestData.Name
	requestType := requestData.Type
	requiresOwnLogin := requestData.RequiresOwnLogin
	loginTypes := requestData.LoginTypes
	organizationDomains := requestData.Config.Domains

	err = h.coreAPIs.Administration.AdmUpdateOrganization(ID, name, string(requestType), *requiresOwnLogin, *loginTypes, *organizationDomains)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypeOrganization, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

//getOrganization gets organization
func (h AdminApisHandler) getOrganization(l *logs.Log, r *http.Request) logs.HttpResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}
	org, err := h.coreAPIs.Administration.AdmGetOrganization(ID)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeOrganization, nil, err, http.StatusInternalServerError, true)
	}
	if org == nil {
		return l.HttpResponseErrorData(logutils.StatusMissing, model.TypeOrganization, &logutils.FieldArgs{"id": ID}, nil, http.StatusNotFound, false)
	}

	responseData := organizationToDef(org)
	data, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeOrganization, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

//getOrganizations gets organizations
func (h AdminApisHandler) getOrganizations(l *logs.Log, r *http.Request) logs.HttpResponse {
	organizations, err := h.coreAPIs.Administration.AdmGetOrganizations()
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeOrganization, nil, err, http.StatusInternalServerError, true)
	}
	var response []Def.Organization
	for _, organization := range organizations {
		r := organizationToDef(&organization)
		response = append(response, *r)
	}

	data, err := json.Marshal(response)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeOrganization, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

func (h AdminApisHandler) getServiceRegistrations(l *logs.Log, r *http.Request) logs.HttpResponse {
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

func (h AdminApisHandler) registerService(l *logs.Log, r *http.Request) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionRead, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ServiceReg
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeServiceReg, nil, err, http.StatusBadRequest, true)
	}

	serviceReg, err := serviceRegFromDef(&requestData)
	if err != nil {
		return l.HttpResponseErrorData(logutils.StatusInvalid, model.TypeServiceReg, nil, err, http.StatusBadRequest, true)
	}

	err = h.coreAPIs.Auth.RegisterService(serviceReg)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionCreate, model.TypeServiceReg, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h AdminApisHandler) updateServiceRegistration(l *logs.Log, r *http.Request) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return l.HttpResponseErrorData(logutils.StatusInvalid, logutils.TypeRequestBody, nil, err, http.StatusBadRequest, false)
	}

	var requestData Def.ServiceReg
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeServiceReg, nil, err, http.StatusBadRequest, true)
	}

	serviceReg, err := serviceRegFromDef(&requestData)
	if err != nil {
		return l.HttpResponseErrorData(logutils.StatusInvalid, model.TypeServiceReg, nil, err, http.StatusBadRequest, true)
	}

	err = h.coreAPIs.Auth.UpdateServiceRegistration(serviceReg)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypeServiceReg, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h AdminApisHandler) deregisterService(l *logs.Log, r *http.Request) logs.HttpResponse {
	serviceID := r.URL.Query().Get("id")
	if serviceID == "" {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}

	err := h.coreAPIs.Auth.DeregisterService(serviceID)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionDelete, model.TypeServiceReg, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

func (h AdminApisHandler) getApplication(l *logs.Log, r *http.Request) logs.HttpResponse {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("id"), nil, http.StatusBadRequest, false)
	}
	app, err := h.coreAPIs.Administration.AdmGetApplication(ID)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeApplication, nil, err, http.StatusInternalServerError, true)
	}
	if app == nil {
		return l.HttpResponseErrorData(logutils.StatusMissing, model.TypeApplication, &logutils.FieldArgs{"id": ID}, nil, http.StatusNotFound, false)
	}

	responseData := applicationToDef(app)
	data, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeApplication, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

//createApplication creates an application
func (h AdminApisHandler) createApplication(l *logs.Log, r *http.Request) logs.HttpResponse {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		l.Errorf("Error on marshal create application - %s\n", err.Error())
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeApplication, nil, err, http.StatusInternalServerError, false)
	}

	var requestData Def.Application
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		l.Errorf("Error on unmarshal the create application - %s\n", err.Error())
		return l.HttpResponseErrorAction(logutils.ActionUnmarshal, model.TypeApplication, nil, err, http.StatusBadRequest, true)
	}

	name := requestData.Name
	versions := requestData.Versions

	_, err = h.coreAPIs.Administration.AdmCreateApplication(name, *versions)
	if err != nil {
		l.Errorf(err.Error())
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeApplication, nil, err, http.StatusInternalServerError, true)
	}

	headers := map[string]string{}
	headers["Content-Type"] = "text/plain"
	return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeApplication, nil, err, http.StatusInternalServerError, false)
}

//getGlobalGroups gets global groups
func (h AdminApisHandler) getGlobalGroups(l *logs.Log, r *http.Request) logs.HttpResponse {
	params := mux.Vars(r)
	ID := params["_id"]
	name := params["name"]
	if len(ID) <= 0 {
		return l.HttpResponseErrorData(logutils.StatusMissing, logutils.TypeQueryParam, logutils.StringArgs("ID"), nil, http.StatusBadRequest, false)
	}
	globalGroup, err := h.coreAPIs.Administration.AdmGetGlobalGroups(&ID, &name)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionGet, model.TypeGlobalGroup, nil, err, http.StatusInternalServerError, true)
	}
	if globalGroup == nil {
		return l.HttpResponseErrorData(logutils.StatusMissing, model.TypeGlobalGroup, &logutils.FieldArgs{"id": ID}, nil, http.StatusNotFound, false)
	}

	responseData := globalGroupListToDef(globalGroup)
	data, err := json.Marshal(responseData)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, model.TypeGlobalGroup, nil, err, http.StatusInternalServerError, false)
	}
	return l.HttpResponseSuccessJSON(data)
}

//NewAdminApisHandler creates new admin rest Handler instance
func NewAdminApisHandler(coreAPIs *core.APIs) AdminApisHandler {
	return AdminApisHandler{coreAPIs: coreAPIs}
}
