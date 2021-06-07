package web

import (
	"core-building-block/core"
	"net/http"
)

//AdminApisHandler handles the admin rest APIs implementation
type AdminApisHandler struct {
	app *core.Application
}

//NewAdminApisHandler creates new admin rest Handler instance
func NewAdminApisHandler(app *core.Application) AdminApisHandler {
	return AdminApisHandler{app: app}
}
