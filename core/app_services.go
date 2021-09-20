package core

import (
	"core-building-block/core/model"

	"github.com/rokmetro/logging-library/logs"
)

func (app *application) serGetProfile(ID string) (*model.Profile, error) {
	return app.storage.FindProfile(ID)
}

func (app *application) serUpdateProfile(profile *model.Profile, ID string) error {
	return app.storage.UpdateProfile(profile, ID)
}

func (app *application) serGetAuthTest(l *logs.Log) string {
	return "Services - Auth - test"
}

func (app *application) serGetCommonTest(l *logs.Log) string {
	return "Services - Common - test"
}
