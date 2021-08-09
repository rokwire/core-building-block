package web

import (
	"core-building-block/core"
	"net/http"

	"github.com/rokmetro/logging-library/logs"
)

//DefaultApisHandler handles default APIs implementation - version etc
type DefaultApisHandler struct {
	coreAPIs *core.APIs
}

//getVersion gives the service version
func (h DefaultApisHandler) getVersion(l *logs.Log, r *http.Request) logs.HttpResponse {
	version := h.coreAPIs.GetVersion()

	return l.HttpResponseSuccessMessage(version)
}

//NewDefaultApisHandler creates new rest services Handler instance
func NewDefaultApisHandler(coreAPIs *core.APIs) DefaultApisHandler {
	return DefaultApisHandler{coreAPIs: coreAPIs}
}
