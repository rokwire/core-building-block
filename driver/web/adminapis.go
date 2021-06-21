package web

import (
	"core-building-block/core"
	"core-building-block/core/model"
	"core-building-block/utils"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
)

//AdminApisHandler handles the admin rest APIs implementation
type AdminApisHandler struct {
	app *core.Application
}

//GetTest TODO get test
func (h AdminApisHandler) GetTest(logging utils.Logging, w http.ResponseWriter, r *http.Request) {
	res := h.app.Administration.AdmGetTest()
	w.Write([]byte(res))
}

//GetTestModel gives a test model instance
func (h AdminApisHandler) GetTestModel(logging utils.Logging, w http.ResponseWriter, r *http.Request) {
	res := h.app.Administration.AdmGetTestModel()
	w.Write([]byte(res))
}

//NewAdminApisHandler creates new admin rest Handler instance
func NewAdminApisHandler(app *core.Application) AdminApisHandler {
	return AdminApisHandler{app: app}
}

//GetGlobalConfig gets the global config
func (h AdminApisHandler) GetGlobalConfigs(logging utils.Logging, w http.ResponseWriter, r *http.Request) {
	configs, err := h.app.Administration.GetGlobalConfigs()
	if err != nil {
		log.Printf("Error config - %s\n", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(configs)
	if err != nil {
		log.Println(data)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

//UpdateGlobalConfig updates the global config
func (h AdminApisHandler) UpdateGlobalConfig(logging utils.Logging, w http.ResponseWriter, r *http.Request) {
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}

	var config model.GlobalConfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	err = h.app.Administration.UpdateGlobalConfig(&config)
	if err != nil {
		log.Printf("Error on updating global config - %s\n", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Successfully updated"))
}
