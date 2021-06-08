package web

import (
	"core-building-block/core"
	"net/http"
)

//ServicesApisHandler handles the rest APIs implementation
type ServicesApisHandler struct {
	app *core.Application
}

//GetTest TODO get test
func (h ServicesApisHandler) GetTest(w http.ResponseWriter, r *http.Request) {
	res := h.app.Services.SerGetTest()
	w.Write([]byte(res))
}

//NewServicesApisHandler creates new rest services Handler instance
func NewServicesApisHandler(app *core.Application) ServicesApisHandler {
	return ServicesApisHandler{app: app}
}
