package web

import (
	"core-building-block/core"
	"net/http"
)

//ServicesApisHandler handles the rest APIs implementation
type ServicesApisHandler struct {
	app *core.Application
}

//NewServicesApisHandler creates new rest services Handler instance
func NewServicesApisHandler(app *core.Application) ServicesApisHandler {
	return ServicesApisHandler{app: app}
}
func (h ServicesApisHandler) SerVersion(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(h.app.Services.SerGetVersion()))
}
