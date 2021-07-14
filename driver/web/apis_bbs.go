package web

import (
	"core-building-block/core"
	"net/http"

	log "github.com/rokmetro/logging-library/loglib"
)

//BBsApisHandler handles the APIs implementation used by the platform building blocks
type BBsApisHandler struct {
	coreAPIs *core.APIs
}

//GetTest TODO get test
func (h BBsApisHandler) GetTest(l *log.Log, w http.ResponseWriter, r *http.Request) (*errorResponse, *successResponse) {
	res := h.coreAPIs.BBs.BBsGetTest()

	return nil, &successResponse{responseCode: http.StatusOK, body: []byte(res)}
}

//NewBBsApisHandler creates new bbs Handler instance
func NewBBsApisHandler(coreAPIs *core.APIs) BBsApisHandler {
	return BBsApisHandler{coreAPIs: coreAPIs}
}
