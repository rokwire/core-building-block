package web

import (
	"core-building-block/core"
	"core-building-block/utils"
	"net/http"
)

//ServicesApisHandler handles the rest APIs implementation
type ServicesApisHandler struct {
	app *core.Application
}

//GetAuthTest TODO get test
func (h ServicesApisHandler) GetAuthTest(logging utils.Logging, w http.ResponseWriter, r *http.Request) {
	res := h.app.Services.SerGetAuthTest(logging)
	w.Write([]byte(res))
}

//GetCommonTest TODO get test
func (h ServicesApisHandler) GetCommonTest(logging utils.Logging, w http.ResponseWriter, r *http.Request) {
	res := h.app.Services.SerGetCommonTest(logging)
	w.Write([]byte(res))
}

//SerVersion gives the service version
func (h ServicesApisHandler) SerVersion(logging utils.Logging, w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(h.app.Services.SerGetVersion(logging)))
}

//NewServicesApisHandler creates new rest services Handler instance
func NewServicesApisHandler(app *core.Application) ServicesApisHandler {
	return ServicesApisHandler{app: app}
}
