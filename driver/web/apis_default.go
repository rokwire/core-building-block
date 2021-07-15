package web

import (
	"core-building-block/core"
	"net/http"

	log "github.com/rokmetro/logging-library/loglib"
)

//DefaultApisHandler handles default APIs implementation - version etc
type DefaultApisHandler struct {
	coreAPIs *core.APIs
}

//GetVersion gives the service version
func (h DefaultApisHandler) GetVersion(l *log.Log, w http.ResponseWriter, r *http.Request) response {
	version := h.coreAPIs.GetVersion()

	headers := map[string]string{}
	headers["Content-Type"] = "text/plain"
	return createSuccessResponse(version, headers, http.StatusOK)
}

//NewDefaultApisHandler creates new rest services Handler instance
func NewDefaultApisHandler(coreAPIs *core.APIs) DefaultApisHandler {
	return DefaultApisHandler{coreAPIs: coreAPIs}
}
