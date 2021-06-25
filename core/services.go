package core

import (
	log "github.com/rokmetro/logging-library/loglib"
)

func (app *Application) serGetVersion(l *log.Log) string {
	return app.version
}

func (app *Application) serGetAuthTest(l *log.Log) string {
	return "Services - Auth - test"
}

func (app *Application) serGetCommonTest(l *log.Log) string {
	return "Services - Common - test"
}
