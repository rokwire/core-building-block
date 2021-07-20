package web

import (
	"core-building-block/core"
	"core-building-block/core/model"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"

	"gopkg.in/go-playground/validator.v9"

	"github.com/gorilla/mux"
	"github.com/rokmetro/auth-library/authservice"
	log "github.com/rokmetro/logging-library/loglib"
)

//AdminApisHandler handles the admin rest APIs implementation
type AdminApisHandler struct {
	coreAPIs *core.APIs
}

//GetTest TODO get test
func (h AdminApisHandler) GetTest(l *log.Log, w http.ResponseWriter, r *http.Request) {
	res := h.coreAPIs.Administration.AdmGetTest()
	w.Write([]byte(res))
}

//GetTestModel gives a test model instance
func (h AdminApisHandler) GetTestModel(l *log.Log, w http.ResponseWriter, r *http.Request) {
	res := h.coreAPIs.Administration.AdmGetTestModel()
	w.Write([]byte(res))
}

type createGlobalConfigRequest struct {
	Setting string `json:"setting" validate:"required"`
}

//CreateGlobalConfig creates a global config
func (h AdminApisHandler) CreateGlobalConfig(l *log.Log, w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		l.RequestErrorAction(w, log.ActionRead, log.TypeRequestBody, nil, err, http.StatusBadRequest, false)
		return
	}

	var requestData createGlobalConfigRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		l.RequestErrorAction(w, log.ActionUnmarshal, model.TypeGlobalConfig, nil, err, http.StatusBadRequest, true)
		return
	}

	validate := validator.New()
	err = validate.Struct(requestData)
	if err != nil {
		l.RequestErrorAction(w, log.ActionValidate, model.TypeGlobalConfig, nil, err, http.StatusBadRequest, true)
		return
	}
	setting := requestData.Setting

	_, err = h.coreAPIs.Administration.AdmCreateGlobalConfig(setting)
	if err != nil {
		l.RequestErrorAction(w, log.ActionCreate, model.TypeGlobalConfig, nil, err, http.StatusInternalServerError, true)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Successfully created"))
}

//NewAdminApisHandler creates new admin rest Handler instance
func NewAdminApisHandler(coreAPIs *core.APIs) AdminApisHandler {
	return AdminApisHandler{coreAPIs: coreAPIs}
}

type responseGlobalConfig struct {
	Setting string `json:"setting"`
}

//GetGlobalConfig gets config
func (h AdminApisHandler) GetGlobalConfig(l *log.Log, w http.ResponseWriter, r *http.Request) {
	config, err := h.coreAPIs.Administration.AdmGetGlobalConfig()
	if err != nil {
		l.RequestErrorAction(w, log.ActionGet, model.TypeGlobalConfig, nil, err, http.StatusInternalServerError, true)
		return
	}

	var responseData *responseGlobalConfig
	if config != nil {
		responseData = &responseGlobalConfig{Setting: config.Setting}
	}
	data, err := json.Marshal(responseData)
	if err != nil {
		l.RequestErrorAction(w, log.ActionMarshal, model.TypeGlobalConfig, nil, err, http.StatusInternalServerError, false)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

type updateGlobalConfig struct {
	Setting string `json:"setting" validate:"required"`
}

//UpdateGlobalConfig updates global config
func (h AdminApisHandler) UpdateGlobalConfig(l *log.Log, w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		l.RequestErrorAction(w, log.ActionRead, log.TypeRequestBody, nil, err, http.StatusBadRequest, false)
		return
	}

	var updateConfig updateGlobalConfig
	err = json.Unmarshal(data, &updateConfig)
	if err != nil {
		l.RequestErrorAction(w, log.ActionUnmarshal, model.TypeGlobalConfig, nil, err, http.StatusBadRequest, true)
		return
	}

	validate := validator.New()
	err = validate.Struct(updateConfig)
	if err != nil {
		l.RequestErrorAction(w, log.ActionValidate, model.TypeGlobalConfig, nil, err, http.StatusBadRequest, true)
		return
	}
	setting := updateConfig.Setting

	err = h.coreAPIs.Administration.AdmUpdateGlobalConfig(setting)
	if err != nil {
		l.RequestErrorAction(w, log.ActionUpdate, model.TypeGlobalConfig, nil, err, http.StatusInternalServerError, true)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Successfully created"))
}

type createOrganizationRequest struct {
	Name                string   `json:"name" validate:"required"`
	Type                string   `json:"type" validate:"required,oneof=micro small medium large huge"`
	RequiresOwnLogin    *bool    `json:"requires_own_login" validate:"required"`
	LoginTypes          []string `json:"login_types"`
	OrganizationDomains []string `json:"organization_domains"`
}

//CreateOrganization creates organization
func (h AdminApisHandler) CreateOrganization(l *log.Log, w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		l.RequestErrorAction(w, log.ActionRead, log.TypeRequestBody, nil, err, http.StatusBadRequest, false)
		return
	}

	var requestData createOrganizationRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		l.RequestErrorAction(w, log.ActionUnmarshal, model.TypeOrganization, nil, err, http.StatusBadRequest, true)
		return
	}

	validate := validator.New()
	err = validate.Struct(requestData)
	if err != nil {
		l.RequestErrorAction(w, log.ActionValidate, model.TypeOrganization, nil, err, http.StatusBadRequest, true)
		return
	}

	name := requestData.Name
	requestType := requestData.Type
	requiresOwnLogin := requestData.RequiresOwnLogin
	loginTypes := requestData.LoginTypes
	organizationDomains := requestData.OrganizationDomains

	_, err = h.coreAPIs.Administration.AdmCreateOrganization(name, requestType, *requiresOwnLogin, loginTypes, organizationDomains)
	if err != nil {
		l.RequestErrorAction(w, log.ActionCreate, model.TypeOrganization, nil, err, http.StatusInternalServerError, true)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Successfully created"))
}

type updateOrganizationRequest struct {
	Name                string   `json:"name" validate:"required"`
	Type                string   `json:"type" validate:"required,oneof=micro small medium large huge"`
	RequiresOwnLogin    *bool    `json:"requires_own_login" validate:"required"`
	LoginTypes          []string `json:"login_types"`
	OrganizationDomains []string `json:"organization_domains"`
}

//UpdateOrganization updates organization
func (h AdminApisHandler) UpdateOrganization(l *log.Log, w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		l.RequestErrorData(w, log.StatusMissing, log.TypeQueryParam, log.StringArgs("id"), nil, http.StatusBadRequest, false)
		return
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		l.RequestErrorData(w, log.StatusInvalid, log.TypeRequestBody, nil, err, http.StatusBadRequest, false)
		return
	}

	var requestData updateOrganizationRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		l.RequestErrorAction(w, log.ActionUnmarshal, model.TypeOrganization, nil, err, http.StatusBadRequest, true)
		return
	}

	validate := validator.New()
	err = validate.Struct(requestData)
	if err != nil {
		l.RequestErrorAction(w, log.ActionValidate, model.TypeOrganization, nil, err, http.StatusBadRequest, true)
		return
	}

	name := requestData.Name
	requestType := requestData.Type
	requiresOwnLogin := requestData.RequiresOwnLogin
	loginTypes := requestData.LoginTypes
	organizationDomains := requestData.OrganizationDomains

	err = h.coreAPIs.Administration.AdmUpdateOrganization(ID, name, requestType, *requiresOwnLogin, loginTypes, organizationDomains)
	if err != nil {
		l.RequestErrorAction(w, log.ActionUpdate, model.TypeOrganization, nil, err, http.StatusInternalServerError, true)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Successfully updated"))
}

//GetServiceRegistrations gets the requested service registrations
func (h AdminApisHandler) GetServiceRegistrations(l *log.Log, w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	serviceIDsParam := params["service_ids"]
	if len(serviceIDsParam) <= 0 {
		l.RequestErrorData(w, log.StatusMissing, log.TypeQueryParam, log.StringArgs("service_ids"), nil, http.StatusBadRequest, false)
		return
	}
	serviceIDs := strings.Split(serviceIDsParam, ",")

	serviceRegs, err := h.coreAPIs.Auth.GetServiceRegistrations(serviceIDs)
	if err != nil {
		l.RequestErrorAction(w, log.ActionGet, model.TypeServiceReg, nil, err, http.StatusInternalServerError, true)
		return
	}

	data, err := json.Marshal(serviceRegs)
	if err != nil {
		l.RequestErrorAction(w, log.ActionMarshal, model.TypeServiceReg, nil, err, http.StatusInternalServerError, false)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

//RegisterService creates a new service registration
func (h AdminApisHandler) RegisterService(l *log.Log, w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		l.RequestErrorAction(w, log.ActionRead, log.TypeRequestBody, nil, err, http.StatusBadRequest, false)
		return
	}

	var requestData *authservice.ServiceReg
	err = json.Unmarshal(data, requestData)
	if err != nil {
		l.RequestErrorAction(w, log.ActionUnmarshal, model.TypeServiceReg, nil, err, http.StatusBadRequest, true)
		return
	}

	validate := validator.New()
	err = validate.Struct(requestData)
	if err != nil {
		l.RequestErrorAction(w, log.ActionValidate, model.TypeServiceReg, nil, err, http.StatusBadRequest, true)
		return
	}

	err = h.coreAPIs.Auth.RegisterService(requestData)
	if err != nil {
		l.RequestErrorAction(w, log.ActionCreate, model.TypeServiceReg, nil, err, http.StatusInternalServerError, true)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Successfully registered"))
}

//UpdateServiceRegistration updates am existing service registration
func (h AdminApisHandler) UpdateServiceRegistration(l *log.Log, w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		l.RequestErrorData(w, log.StatusInvalid, log.TypeRequestBody, nil, err, http.StatusBadRequest, false)
		return
	}

	var requestData *authservice.ServiceReg
	err = json.Unmarshal(data, requestData)
	if err != nil {
		l.RequestErrorAction(w, log.ActionUnmarshal, model.TypeServiceReg, nil, err, http.StatusBadRequest, true)
		return
	}

	validate := validator.New()
	err = validate.Struct(requestData)
	if err != nil {
		l.RequestErrorAction(w, log.ActionValidate, model.TypeServiceReg, nil, err, http.StatusBadRequest, true)
		return
	}

	err = h.coreAPIs.Auth.UpdateServiceRegistration(requestData)
	if err != nil {
		l.RequestErrorAction(w, log.ActionUpdate, model.TypeServiceReg, nil, err, http.StatusInternalServerError, true)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Successfully updated"))
}

//DeregisterService deregisters the requested service
func (h AdminApisHandler) DeregisterService(l *log.Log, w http.ResponseWriter, r *http.Request) {
	service_id := r.URL.Query().Get("service_id")
	if service_id != "" {
		l.RequestErrorData(w, log.StatusMissing, log.TypeQueryParam, log.StringArgs("service_id"), nil, http.StatusBadRequest, false)
		return
	}

	err := h.coreAPIs.Auth.DeregisterService(service_id)
	if err != nil {
		l.RequestErrorAction(w, log.ActionDelete, model.TypeServiceReg, nil, err, http.StatusInternalServerError, true)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Successfully updated"))
}
