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

//GetAuthTest TODO get test
func (h ServicesApisHandler) GetAuthTest(l *log.Log, w http.ResponseWriter, r *http.Request) (*errorResponse, *successResponse) {
	res := h.coreAPIs.Services.SerGetAuthTest(l)

	return nil, &successResponse{responseCode: http.StatusOK, body: []byte(res)}
}

//GetCommonTest TODO get test
func (h ServicesApisHandler) GetCommonTest(l *log.Log, w http.ResponseWriter, r *http.Request) (*errorResponse, *successResponse) {
	res := h.coreAPIs.Services.SerGetCommonTest(l)

	return nil, &successResponse{responseCode: http.StatusOK, body: []byte(res)}
}

//NewServicesApisHandler creates new rest services Handler instance
func NewServicesApisHandler(coreAPIs *core.APIs) ServicesApisHandler {
	return ServicesApisHandler{coreAPIs: coreAPIs}
}
