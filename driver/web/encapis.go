package web

import (
	"core-building-block/core"
	"net/http"
)

//EncApisHandler handles the APIs implementation used by the Encryption BB
type EncApisHandler struct {
	app *core.Application
}

//GetTest TODO get test
func (h EncApisHandler) GetTest(w http.ResponseWriter, r *http.Request) {
	res := h.app.Encryption.EncGetTest()
	w.Write([]byte(res))
}

//NewEncApisHandler creates new enc Handler instance
func NewEncApisHandler(app *core.Application) EncApisHandler {
	return EncApisHandler{app: app}
}
