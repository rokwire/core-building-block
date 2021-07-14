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

//GetTest TODO get test
func (h EncApisHandler) GetTest(l *log.Log, w http.ResponseWriter, r *http.Request) (*errorResponse, *successResponse) {
	res := h.coreAPIs.Encryption.EncGetTest()

	return nil, &successResponse{responseCode: http.StatusOK, body: []byte(res)}
}

//NewEncApisHandler creates new enc Handler instance
func NewEncApisHandler(coreAPIs *core.APIs) EncApisHandler {
	return EncApisHandler{coreAPIs: coreAPIs}
}
