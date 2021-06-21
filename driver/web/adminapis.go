package web

import (
	"core-building-block/core"
	"core-building-block/utils"
	"encoding/json"
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

func (h AdminApisHandler) CreateGlobalConfig(logging utils.Logging, w http.ResponseWriter, r *http.Request) {
	createConf, err := h.app.Administration.CreateGlobalConfig(r.URL.Host)
	if err != nil {
		log.Printf("Error config - %s\n", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	data, err := json.Marshal(createConf)
	if err != nil {
		log.Println(data)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}
