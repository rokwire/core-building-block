package web

import (
	"core-building-block/core"
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
		l.Errorf("Error on marshal create global config - %s\n", err.Error())
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	var requestData createGlobalConfigRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		l.Errorf("Error on unmarshal the create global config data - %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//validate
	validate := validator.New()
	err = validate.Struct(requestData)
	if err != nil {
		l.Errorf("Error on validating create global config data - %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	setting := requestData.Setting

	_, err = h.coreAPIs.Administration.AdmCreateGlobalConfig(setting)
	if err != nil {
		l.Errorf(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
		l.Errorf("Error on getting config - %s\n", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	var responseData *responseGlobalConfig
	if config != nil {
		responseData = &responseGlobalConfig{Setting: config.Setting}
	}
	data, err := json.Marshal(responseData)
	if err != nil {
		l.Errorf("Error on marshal the config")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
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
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	var updateConfig updateGlobalConfig
	err = json.Unmarshal(data, &updateConfig)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//validate
	validate := validator.New()
	err = validate.Struct(updateConfig)
	if err != nil {
		l.Errorf("Error on validating create global config data - %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	setting := updateConfig.Setting

	err = h.coreAPIs.Administration.AdmUpdateGlobalConfig(setting)
	if err != nil {
		l.Errorf(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
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
		l.Errorf("Error on marshal create organization - %s\n", err.Error())
		return
	}
	var requestData createOrganizationRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		l.Errorf("Error on unmarshal the create organization  - %s\n", err.Error())
		return
	}

	//validate
	validate := validator.New()
	err = validate.Struct(requestData)
	if err != nil {
		l.Errorf("Error on validating create organization  data - %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	name := requestData.Name
	requestType := requestData.Type
	requiresOwnLogin := requestData.RequiresOwnLogin
	loginTypes := requestData.LoginTypes
	organizationDomains := requestData.OrganizationDomains

	_, err = h.coreAPIs.Administration.AdmCreateOrganization(name, requestType, *requiresOwnLogin, loginTypes, organizationDomains)
	if err != nil {
		l.Errorf("Error on creating an organization - %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Successfully created"))
}

type getOrganizationResponse struct {
	Name                string   `json:"name" validate:"required"`
	Type                string   `json:"type" validate:"required,oneof=micro small medium large huge"`
	RequiresOwnLogin    *bool    `json:"requires_own_login" validate:"required"`
	LoginTypes          []string `json:"login_types"`
	OrganizationDomains []string `json:"organization_domains"`
}

//GetOrganization gets organization
func (h AdminApisHandler) GetOrganization(l *log.Log, w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		http.Error(w, "id is required", http.StatusBadRequest)
		return
	}
	getOrg, err := h.coreAPIs.Administration.AdmGetOrganization(ID)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	var responseData *getOrganizationResponse
	if getOrg != nil {
		responseData = &getOrganizationResponse{Name: getOrg.Name, Type: getOrg.Type,
			RequiresOwnLogin: &getOrg.RequiresOwnLogin, LoginTypes: getOrg.LoginTypes, OrganizationDomains: getOrg.Config.Domains}
	}
	data, err := json.Marshal(responseData)
	if err != nil {
		l.Errorf("Error on marshal the config")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

//UpdateOrganization updates organization
func (h AdminApisHandler) UpdateOrganization(l *log.Log, w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		http.Error(w, "ID is required", http.StatusBadRequest)
		return
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		l.Errorf("Error on marshal update organization - %s\n", err.Error())
		return
	}
	var requestData updateOrganizationRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		l.Errorf("Error on unmarshal the update organization  - %s\n", err.Error())
		return
	}

	//validate
	validate := validator.New()
	err = validate.Struct(requestData)
	if err != nil {
		l.Errorf("Error on validating update organization  data - %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	name := requestData.Name
	requestType := requestData.Type
	requiresOwnLogin := requestData.RequiresOwnLogin
	loginTypes := requestData.LoginTypes
	organizationDomains := requestData.OrganizationDomains

	err = h.coreAPIs.Administration.AdmUpdateOrganization(ID, name, requestType, *requiresOwnLogin, loginTypes, organizationDomains)
	if err != nil {
		l.Errorf("Error on updating an organization - %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Successfully updated"))
}
