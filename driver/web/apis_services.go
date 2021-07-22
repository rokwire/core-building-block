package web

import (
	"core-building-block/core"
	"net/http"

	log "github.com/rokmetro/logging-library/loglib"
)

//ServicesApisHandler handles the rest APIs implementation
type ServicesApisHandler struct {
	coreAPIs *core.APIs
}

//getAuthTest TODO get test
func (h ServicesApisHandler) getAuthTest(l *log.Log, w http.ResponseWriter, r *http.Request) response {
	res := h.coreAPIs.Services.SerGetAuthTest(l)

	headers := map[string]string{}
	headers["Content-Type"] = "text/plain"
	return createSuccessResponse(res, headers, http.StatusOK)
}

//getCommonTest TODO get test
func (h ServicesApisHandler) getCommonTest(l *log.Log, w http.ResponseWriter, r *http.Request) response {
	res := h.coreAPIs.Services.SerGetCommonTest(l)

	headers := map[string]string{}
	headers["Content-Type"] = "text/plain"
	return createSuccessResponse(res, headers, http.StatusOK)
}

//NewServicesApisHandler creates new rest services Handler instance
func NewServicesApisHandler(coreAPIs *core.APIs) ServicesApisHandler {
	return ServicesApisHandler{coreAPIs: coreAPIs}
}
