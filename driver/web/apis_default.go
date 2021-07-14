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
func (h DefaultApisHandler) GetVersion(l *log.Log, w http.ResponseWriter, r *http.Request) (*errorResponse, *successResponse) {
	version := h.coreAPIs.GetVersion()

	contentType := "text/plain"
	return nil, &successResponse{responseCode: http.StatusOK, contentType: &contentType, body: []byte(version)}
}

//NewDefaultApisHandler creates new rest services Handler instance
func NewDefaultApisHandler(coreAPIs *core.APIs) DefaultApisHandler {
	return DefaultApisHandler{coreAPIs: coreAPIs}
}
