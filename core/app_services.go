package core

import (
	"core-building-block/core/model"

	"github.com/rokmetro/logging-library/logs"
)

func (app *application) serGetPII(ID string) (*model.UserProfile, error) {
	return app.storage.FindPII(ID)
}

func (app *application) serUpdatePII(profile *model.UserProfile, ID string) error {
	return app.storage.UpdatePII(profile, ID, false)
}

func (app *application) serDeletePII(ID string) error {
	return app.storage.UpdatePII(nil, ID, true)
}

func (app *application) serGetAuthTest(l *logs.Log) string {
	return "Services - Auth - test"
}

func (app *application) serGetCommonTest(l *logs.Log) string {
	return "Services - Common - test"
}
