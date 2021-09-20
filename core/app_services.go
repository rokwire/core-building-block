package core

import "github.com/rokmetro/logging-library/logs"

func (app *application) serDeleteAccount(id string) error {
	return app.storage.DeleteAccount(id)
}

func (app *application) serGetAuthTest(l *logs.Log) string {
	return "Services - Auth - test"
}

func (app *application) serGetCommonTest(l *logs.Log) string {
	return "Services - Common - test"
}
