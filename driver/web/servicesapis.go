package web

import (
	"core-building-block/core"
	"net/http"
)

//ServicesApisHandler handles the rest APIs implementation
type ServicesApisHandler struct {
	app *core.Application
}

//GetAuthTest TODO get test
func (h ServicesApisHandler) GetAuthTest(w http.ResponseWriter, r *http.Request) {
	res := h.app.Services.SerGetAuthTest()
	w.Write([]byte(res))
}

//GetCommonTest TODO get test
func (h ServicesApisHandler) GetCommonTest(w http.ResponseWriter, r *http.Request) {
	res := h.app.Services.SerGetCommonTest()
	w.Write([]byte(res))
}

//NewServicesApisHandler creates new rest services Handler instance
func NewServicesApisHandler(app *core.Application) ServicesApisHandler {
	return ServicesApisHandler{app: app}
}
func (h ServicesApisHandler) SerVersion(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(h.app.Services.SerGetVersion()))
}
