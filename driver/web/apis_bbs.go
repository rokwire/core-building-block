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

//getTest TODO get test
func (h BBsApisHandler) getTest(l *log.Log, r *http.Request) log.HttpResponse {
	res := h.coreAPIs.BBs.BBsGetTest()

	return l.HttpResponseSuccessMessage(res)
}

//NewBBsApisHandler creates new bbs Handler instance
func NewBBsApisHandler(coreAPIs *core.APIs) BBsApisHandler {
	return BBsApisHandler{coreAPIs: coreAPIs}
}
