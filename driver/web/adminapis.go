package web

import (
	"core-building-block/core"
	"core-building-block/utils"
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

//NewAdminApisHandler creates new admin rest Handler instance
func NewAdminApisHandler(app *core.Application) AdminApisHandler {
	return AdminApisHandler{app: app}
}
