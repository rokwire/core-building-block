package web

import (
	"core-building-block/core"
	"net/http"

	"github.com/rokwire/core-auth-library-go/tokenauth"
	"github.com/rokwire/logging-library-go/logs"
)

//EncApisHandler handles the APIs implementation used by the Encryption BB
type EncApisHandler struct {
	coreAPIs *core.APIs
}

//getTest TODO get test
func (h EncApisHandler) getTest(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	res := h.coreAPIs.Encryption.EncGetTest()

	return l.HttpResponseSuccessMessage(res)
}

//NewEncApisHandler creates new enc Handler instance
func NewEncApisHandler(coreAPIs *core.APIs) EncApisHandler {
	return EncApisHandler{coreAPIs: coreAPIs}
}
