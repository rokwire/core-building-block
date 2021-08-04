package core

import (
	"core-building-block/core/model"

	"github.com/rokmetro/logging-library/logs"
)

func (app *application) serGetPII(ID string) (*model.UserProfile, error) {
	return app.storage.GetPII(ID)
}

func (app *application) serCreatePII(profile *model.UserProfile, ID string) error {
	return app.storage.CreatePII(profile, ID)
}

func (app *application) serUpdatePII(profile *model.UserProfile, ID string) error {
	return app.storage.UpdatePII(profile, ID)
}

func (app *application) serDeletePII(ID string) error {
	return app.storage.DeletePII(ID)
}

func (app *application) serGetAuthTest(l *logs.Log) string {
	return "Services - Auth - test"
}

func (app *application) serGetCommonTest(l *logs.Log) string {
	return "Services - Common - test"
}
