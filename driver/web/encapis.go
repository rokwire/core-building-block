package web

import (
	"core-building-block/core"
)

//EncApisHandler handles the APIs implementation used by the Encryption BB
type EncApisHandler struct {
	app *core.Application
}

//NewEncApisHandler creates new enc Handler instance
func NewEncApisHandler(app *core.Application) EncApisHandler {
	return EncApisHandler{app: app}
}
