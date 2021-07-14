package web

import (
	"core-building-block/core"
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

//GetTest TODO get test
func (h AdminApisHandler) GetTest(l *log.Log, w http.ResponseWriter, r *http.Request) (*errorResponse, *successResponse) {
	res := h.coreAPIs.Administration.AdmGetTest()

	return nil, &successResponse{responseCode: http.StatusOK, body: []byte(res)}
}

//GetTestModel gives a test model instance
func (h AdminApisHandler) GetTestModel(l *log.Log, w http.ResponseWriter, r *http.Request) (*errorResponse, *successResponse) {
	res := h.coreAPIs.Administration.AdmGetTestModel()

	return nil, &successResponse{responseCode: http.StatusOK, body: []byte(res)}
}

//CreateGlobalConfig creates a global config
func (h AdminApisHandler) CreateGlobalConfig(l *log.Log, w http.ResponseWriter, r *http.Request) (*errorResponse, *successResponse) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		//log.Printf("Error on marshal create global config - %s\n", err.Error())
		return &errorResponse{http.StatusText(http.StatusBadRequest), http.StatusBadRequest}, nil
	}

	var requestData Def.PostAdminGlobalConfigJSONRequestBody
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		//log.Printf("Error on unmarshal the create global config data - %s\n", err.Error())
		return &errorResponse{err.Error(), http.StatusBadRequest}, nil
	}

	//validate
	validate := validator.New()
	err = validate.Struct(requestData)
	if err != nil {
		//log.Printf("Error on validating create global config data - %s\n", err.Error())
		return &errorResponse{err.Error(), http.StatusBadRequest}, nil
	}
	setting := requestData.Setting

	_, err = h.coreAPIs.Administration.AdmCreateGlobalConfig(setting)
	if err != nil {
		//	log.Println(err.Error())
		return &errorResponse{err.Error(), http.StatusInternalServerError}, nil
	}

	contentType := "text/plain"
	return nil, &successResponse{responseCode: http.StatusOK, contentType: &contentType, body: []byte("Successfully created")}
}

//GetGlobalConfig gets config
func (h AdminApisHandler) GetGlobalConfig(l *log.Log, w http.ResponseWriter, r *http.Request) (*errorResponse, *successResponse) {
	config, err := h.coreAPIs.Administration.AdmGetGlobalConfig()
	if err != nil {
		//log.Printf("Error on getting config - %s\n", err)
		return &errorResponse{http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError}, nil
	}

	var responseData *Def.GlobalConfig
	if config != nil {
		responseData = &Def.GlobalConfig{Setting: config.Setting}
	}
	data, err := json.Marshal(responseData)
	if err != nil {
		//log.Println("Error on marshal the config")
		return &errorResponse{http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError}, nil
	}

	contentType := "application/json; charset=utf-8"
	return nil, &successResponse{responseCode: http.StatusOK, contentType: &contentType, body: data}
}

//UpdateGlobalConfig updates global config
func (h AdminApisHandler) UpdateGlobalConfig(l *log.Log, w http.ResponseWriter, r *http.Request) (*errorResponse, *successResponse) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return &errorResponse{http.StatusText(http.StatusBadRequest), http.StatusBadRequest}, nil
	}

	var updateConfig Def.PutAdminGlobalConfigJSONRequestBody
	err = json.Unmarshal(data, &updateConfig)
	if err != nil {
		return &errorResponse{err.Error(), http.StatusBadRequest}, nil
	}

	//validate
	validate := validator.New()
	err = validate.Struct(updateConfig)
	if err != nil {
		//log.Printf("Error on validating create global config data - %s\n", err.Error())
		return &errorResponse{err.Error(), http.StatusBadRequest}, nil
	}
	setting := updateConfig.Setting

	err = h.coreAPIs.Administration.AdmUpdateGlobalConfig(setting)
	if err != nil {
		//	log.Println(err.Error())
		return &errorResponse{err.Error(), http.StatusInternalServerError}, nil
	}

	contentType := "text/plain"
	return nil, &successResponse{responseCode: http.StatusOK, contentType: &contentType, body: []byte("Successfully updated")}
}

//CreateOrganization creates organization
func (h AdminApisHandler) CreateOrganization(l *log.Log, w http.ResponseWriter, r *http.Request) (*errorResponse, *successResponse) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		l.Errorf("Error on marshal create organization - %s\n", err.Error())
		return &errorResponse{http.StatusText(http.StatusBadRequest), http.StatusBadRequest}, nil
	}
	var requestData Def.PostAdminOrganizationsJSONRequestBody
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		l.Errorf("Error on unmarshal the create organization  - %s\n", err.Error())
		return &errorResponse{http.StatusText(http.StatusBadRequest), http.StatusBadRequest}, nil
	}

	//validate
	validate := validator.New()
	err = validate.Struct(requestData)
	if err != nil {
		l.Errorf("Error on validating create organization  data - %s\n", err.Error())
		return &errorResponse{http.StatusText(http.StatusBadRequest), http.StatusBadRequest}, nil
	}

	name := requestData.Name
	requestType := requestData.Type
	requiresOwnLogin := requestData.RequiresOwnLogin
	loginTypes := requestData.LoginTypes
	organizationDomains := requestData.Config.Domains

	_, err = h.coreAPIs.Administration.AdmCreateOrganization(name, string(requestType), *requiresOwnLogin, *loginTypes, *organizationDomains)
	if err != nil {
		l.Errorf("Error on creating an organization - %s\n", err.Error())
		return &errorResponse{err.Error(), http.StatusInternalServerError}, nil
	}

	contentType := "text/plain"
	return nil, &successResponse{responseCode: http.StatusOK, contentType: &contentType, body: []byte("Successfully created")}
}

//UpdateOrganization updates organization
func (h AdminApisHandler) UpdateOrganization(l *log.Log, w http.ResponseWriter, r *http.Request) (*errorResponse, *successResponse) {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return &errorResponse{"ID is required", http.StatusBadRequest}, nil
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		l.Errorf("Error on marshal update organization - %s\n", err.Error())
		return &errorResponse{"ID is required", http.StatusBadRequest}, nil
	}
	var requestData Def.PutAdminOrganizationsIdJSONRequestBody
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		l.Errorf("Error on unmarshal the update organization  - %s\n", err.Error())
		return &errorResponse{http.StatusText(http.StatusBadRequest), http.StatusBadRequest}, nil
	}

	//validate
	validate := validator.New()
	err = validate.Struct(requestData)
	if err != nil {
		l.Errorf("Error on validating update organization  data - %s\n", err.Error())
		return &errorResponse{http.StatusText(http.StatusBadRequest), http.StatusBadRequest}, nil
	}

	name := requestData.Name
	requestType := requestData.Type
	requiresOwnLogin := requestData.RequiresOwnLogin
	loginTypes := requestData.LoginTypes
	organizationDomains := requestData.Config.Domains

	err = h.coreAPIs.Administration.AdmUpdateOrganization(ID, name, string(requestType), *requiresOwnLogin, *loginTypes, *organizationDomains)
	if err != nil {
		l.Errorf("Error on updating an organization - %s\n", err.Error())
		return &errorResponse{err.Error(), http.StatusInternalServerError}, nil
	}

	contentType := "text/plain"
	return nil, &successResponse{responseCode: http.StatusOK, contentType: &contentType, body: []byte("Successfully updated")}
}

//NewAdminApisHandler creates new admin rest Handler instance
func NewAdminApisHandler(coreAPIs *core.APIs) AdminApisHandler {
	return AdminApisHandler{coreAPIs: coreAPIs}
}
