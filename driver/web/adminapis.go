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
