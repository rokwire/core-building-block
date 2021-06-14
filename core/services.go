package core

import (
	"core-building-block/utils"
)

func (app *Application) serGetVersion(logging utils.Logging) string {
	logging.Printf("")
	return app.version
}

func (app *Application) serGetAuthTest(logging utils.Logging) string {
	logging.Printf("")
	return "Services - Auth - test"
}

func (app *Application) serGetCommonTest(logging utils.Logging) string {
	logging.Printf("")
	return "Services - Common - test"
}
