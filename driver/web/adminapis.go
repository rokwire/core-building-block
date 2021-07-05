package web

import (
	"core-building-block/core"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"gopkg.in/go-playground/validator.v9"

	log "github.com/rokmetro/logging-library/loglib"
)

//AdminApisHandler handles the admin rest APIs implementation
type AdminApisHandler struct {
	app *core.Application
}

//GetTest TODO get test
func (h AdminApisHandler) GetTest(l *log.Log, w http.ResponseWriter, r *http.Request) {
	res := h.app.Administration.AdmGetTest()
	w.Write([]byte(res))
}

//GetTestModel gives a test model instance
func (h AdminApisHandler) GetTestModel(l *log.Log, w http.ResponseWriter, r *http.Request) {
	res := h.app.Administration.AdmGetTestModel()
	w.Write([]byte(res))
}

type createGlobalConfigRequest struct {
	Setting string `json:"setting" validate:"required"`
}

//CreateGlobalConfig creates a global config
func (h AdminApisHandler) CreateGlobalConfig(l *log.Log, w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		//log.Printf("Error on marshal create global config - %s\n", err.Error())
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	var requestData createGlobalConfigRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		//log.Printf("Error on unmarshal the create global config data - %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//validate
	validate := validator.New()
	err = validate.Struct(requestData)
	if err != nil {
		//log.Printf("Error on validating create global config data - %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	setting := requestData.Setting

	_, err = h.app.Administration.AdmCreateGlobalConfig(setting)
	if err != nil {
		//	log.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Successfully created"))
}

//NewAdminApisHandler creates new admin rest Handler instance
func NewAdminApisHandler(app *core.Application) AdminApisHandler {
	return AdminApisHandler{app: app}
}

type responseGlobalConfig struct {
	Setting string `json:"setting"`
}

//GetGlobalConfig gets config
func (h AdminApisHandler) GetGlobalConfig(l *log.Log, w http.ResponseWriter, r *http.Request) {
	config, err := h.app.Administration.AdmGetGlobalConfig()
	if err != nil {
		//log.Printf("Error on getting config - %s\n", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	var responseData *responseGlobalConfig
	if config != nil {
		responseData = &responseGlobalConfig{Setting: config.Setting}
	}
	data, err := json.Marshal(responseData)
	if err != nil {
		//log.Println("Error on marshal the config")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

type createOrganizationRequest struct {
	Name             string   `json:"name" validate:"required"`
	Type             string   `json:"type" validate:"required"`
	RequiresOwnLogin *bool    `json:"requires_own_login" validate:"required"`
	LoginTypes       []string `json:"login_types"`
}
type OrganizationResponse struct {
	Name             string   `json:"name"`
	Type             string   `json:"type"`
	RequiresOwnLogin bool     `json:"requires_own_login"`
	LoginTypes       []string `json:"login_types"`
}

//CreateOrganization creates organization
func (h AdminApisHandler) CreateOrganization(l *log.Log, w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		//log.Printf("Error on marshal create organization - %s\n", err.Error())
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


	var requestData createOrganizationRequest
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		//log.Printf("Error on unmarshal the create organization  - %s\n", err.Error())

	var updateConfig updateGlobalConfig
	err = json.Unmarshal(data, &updateConfig)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	//validate
	validate := validator.New()
	err = validate.Struct(requestData)
	if err != nil {
		//log.Printf("Error on validating create organization  data - %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	name := requestData.Name
	requestType := requestData.Type
	requiresOwnLogin := requestData.RequiresOwnLogin
	loginTypes := requestData.LoginTypes

	organization, err := h.app.Administration.AdmCreateOrganization(name, requestType, *requiresOwnLogin, loginTypes)
	err = validate.Struct(updateConfig)
	if err != nil {
		//log.Printf("Error on validating create global config data - %s\n", err.Error())
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	setting := updateConfig.Setting

	err = h.app.Administration.AdmUpdateGlobalConfig(setting)
	if err != nil {
		//	log.Println(err.Error())
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}


	response := OrganizationResponse{Name: organization.Name, Type: organization.Type, RequiresOwnLogin: organization.RequiresOwnLogin, LoginTypes: loginTypes}
	data, err = json.Marshal(response)
	if err != nil {
		//log.Println("Error on marshal")
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
    
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Successfully created"))
}
