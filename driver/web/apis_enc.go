package web

import (
	"core-building-block/core"
	"net/http"

	log "github.com/rokmetro/logging-library/loglib"
)

//EncApisHandler handles the APIs implementation used by the Encryption BB
type EncApisHandler struct {
	coreAPIs *core.APIs
}

//getTest TODO get test
func (h EncApisHandler) getTest(l *log.Log, w http.ResponseWriter, r *http.Request) response {
	res := h.coreAPIs.Encryption.EncGetTest()

	return createSuccessResponse(res, nil, http.StatusOK)
}

//NewEncApisHandler creates new enc Handler instance
func NewEncApisHandler(coreAPIs *core.APIs) EncApisHandler {
	return EncApisHandler{coreAPIs: coreAPIs}
}
