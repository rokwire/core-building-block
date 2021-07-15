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

//getTest TODO get test
func (h AdminApisHandler) getTest(l *log.Log, w http.ResponseWriter, r *http.Request) response {
	res := h.coreAPIs.Administration.AdmGetTest()

	return createSuccessResponse(res, nil, http.StatusOK)
}

//getTestModel gives a test model instance
func (h AdminApisHandler) getTestModel(l *log.Log, w http.ResponseWriter, r *http.Request) response {
	res := h.coreAPIs.Administration.AdmGetTestModel()

	return createSuccessResponse(res, nil, http.StatusOK)
}

//createGlobalConfig creates a global config
func (h AdminApisHandler) createGlobalConfig(l *log.Log, w http.ResponseWriter, r *http.Request) response {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		//log.Printf("Error on marshal create global config - %s\n", err.Error())
		return createErrorResponse(http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}

	var requestData Def.PostAdminGlobalConfigJSONRequestBody
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		//log.Printf("Error on unmarshal the create global config data - %s\n", err.Error())
		return createErrorResponse(err.Error(), http.StatusBadRequest)
	}

	//validate
	validate := validator.New()
	err = validate.Struct(requestData)
	if err != nil {
		//log.Printf("Error on validating create global config data - %s\n", err.Error())
		return createErrorResponse(err.Error(), http.StatusBadRequest)
	}
	setting := requestData.Setting

	_, err = h.coreAPIs.Administration.AdmCreateGlobalConfig(setting)
	if err != nil {
		//	log.Println(err.Error())
		return createErrorResponse(err.Error(), http.StatusInternalServerError)
	}

	headers := map[string]string{}
	headers["Content-Type"] = "text/plain"
	return createSuccessResponse("Successfully created", headers, http.StatusOK)
}

//getGlobalConfig gets config
func (h AdminApisHandler) getGlobalConfig(l *log.Log, w http.ResponseWriter, r *http.Request) response {
	config, err := h.coreAPIs.Administration.AdmGetGlobalConfig()
	if err != nil {
		//log.Printf("Error on getting config - %s\n", err)
		return createErrorResponse(http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	var responseData *Def.GlobalConfig
	if config != nil {
		responseData = &Def.GlobalConfig{Setting: config.Setting}
	}
	data, err := json.Marshal(responseData)
	if err != nil {
		//log.Println("Error on marshal the config")
		return createErrorResponse(http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	}

	headers := map[string]string{}
	headers["Content-Type"] = "application/json; charset=utf-8"
	return createSuccessResponse(string(data), headers, http.StatusOK)
}

//updateGlobalConfig updates global config
func (h AdminApisHandler) updateGlobalConfig(l *log.Log, w http.ResponseWriter, r *http.Request) response {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return createErrorResponse(http.StatusText(http.StatusBadRequest), http.StatusBadRequest)

	}

	var updateConfig Def.PutAdminGlobalConfigJSONRequestBody
	err = json.Unmarshal(data, &updateConfig)
	if err != nil {
		return createErrorResponse(err.Error(), http.StatusBadRequest)

	}

	//validate
	validate := validator.New()
	err = validate.Struct(updateConfig)
	if err != nil {
		//log.Printf("Error on validating create global config data - %s\n", err.Error())
		return createErrorResponse(err.Error(), http.StatusBadRequest)
	}
	setting := updateConfig.Setting

	err = h.coreAPIs.Administration.AdmUpdateGlobalConfig(setting)
	if err != nil {
		//	log.Println(err.Error())
		return createErrorResponse(err.Error(), http.StatusInternalServerError)
	}

	headers := map[string]string{}
	headers["Content-Type"] = "text/plain"
	return createSuccessResponse("Successfully created", headers, http.StatusOK)
}

//createOrganization creates organization
func (h AdminApisHandler) createOrganization(l *log.Log, w http.ResponseWriter, r *http.Request) response {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		l.Errorf("Error on marshal create organization - %s\n", err.Error())
		return createErrorResponse(http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}
	var requestData Def.PostAdminOrganizationsJSONRequestBody
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		l.Errorf("Error on unmarshal the create organization  - %s\n", err.Error())
		return createErrorResponse(http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}

	//validate
	validate := validator.New()
	err = validate.Struct(requestData)
	if err != nil {
		l.Errorf("Error on validating create organization  data - %s\n", err.Error())
		return createErrorResponse(http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}

	name := requestData.Name
	requestType := requestData.Type
	requiresOwnLogin := requestData.RequiresOwnLogin
	loginTypes := requestData.LoginTypes
	organizationDomains := requestData.Config.Domains

	_, err = h.coreAPIs.Administration.AdmCreateOrganization(name, string(requestType), *requiresOwnLogin, *loginTypes, *organizationDomains)
	if err != nil {
		l.Errorf("Error on creating an organization - %s\n", err.Error())
		return createErrorResponse(err.Error(), http.StatusInternalServerError)
	}

	headers := map[string]string{}
	headers["Content-Type"] = "text/plain"
	return createSuccessResponse("Successfully created", headers, http.StatusOK)
}

//updateOrganization updates organization
func (h AdminApisHandler) updateOrganization(l *log.Log, w http.ResponseWriter, r *http.Request) response {
	params := mux.Vars(r)
	ID := params["id"]
	if len(ID) <= 0 {
		return createErrorResponse("ID is required", http.StatusBadRequest)
	}

	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		l.Errorf("Error on marshal update organization - %s\n", err.Error())
		return createErrorResponse("ID is required", http.StatusBadRequest)
	}
	var requestData Def.PutAdminOrganizationsIdJSONRequestBody
	err = json.Unmarshal(data, &requestData)
	if err != nil {
		l.Errorf("Error on unmarshal the update organization  - %s\n", err.Error())
		return createErrorResponse(http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}

	//validate
	validate := validator.New()
	err = validate.Struct(requestData)
	if err != nil {
		l.Errorf("Error on validating update organization  data - %s\n", err.Error())
		return createErrorResponse(http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
	}

	name := requestData.Name
	requestType := requestData.Type
	requiresOwnLogin := requestData.RequiresOwnLogin
	loginTypes := requestData.LoginTypes
	organizationDomains := requestData.Config.Domains

	err = h.coreAPIs.Administration.AdmUpdateOrganization(ID, name, string(requestType), *requiresOwnLogin, *loginTypes, *organizationDomains)
	if err != nil {
		l.Errorf("Error on updating an organization - %s\n", err.Error())
		return createErrorResponse(err.Error(), http.StatusInternalServerError)
	}

	headers := map[string]string{}
	headers["Content-Type"] = "text/plain"
	return createSuccessResponse("Successfully created", headers, http.StatusOK)
}

//NewAdminApisHandler creates new admin rest Handler instance
func NewAdminApisHandler(coreAPIs *core.APIs) AdminApisHandler {
	return AdminApisHandler{coreAPIs: coreAPIs}
}
