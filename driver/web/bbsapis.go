package web

import (
	"core-building-block/core"
	"core-building-block/utils"
	"net/http"
)

//BBsApisHandler handles the APIs implementation used by the platform building blocks
type BBsApisHandler struct {
	app *core.Application
}

//GetTest TODO get test
func (h BBsApisHandler) GetTest(logging utils.Logging, w http.ResponseWriter, r *http.Request) {
	res := h.app.BBs.BBsGetTest()
	w.Write([]byte(res))
}

//NewBBsApisHandler creates new bbs Handler instance
func NewBBsApisHandler(app *core.Application) BBsApisHandler {
	return BBsApisHandler{app: app}
}
