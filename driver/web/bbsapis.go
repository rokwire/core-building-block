package web

import (
	"core-building-block/core"
)

//BBsApisHandler handles the APIs implementation used by the platform building blocks
type BBsApisHandler struct {
	app *core.Application
}

//NewBBsApisHandler creates new bbs Handler instance
func NewBBsApisHandler(app *core.Application) BBsApisHandler {
	return BBsApisHandler{app: app}
}
