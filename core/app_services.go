package core

import (
	"core-building-block/core/model"

	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logs"
	"github.com/rokmetro/logging-library/logutils"
)

func (app *application) serGetAuthTest(l *logs.Log) string {
	return "Services - Auth - test"
}

func (app *application) serGetCommonTest(l *logs.Log) string {
	return "Services - Common - test"
}

func (app *application) createAnonymousProfile(l *logs.Log, profile *model.AnonymousProfile) (*model.AnonymousProfile, error) {
	organization, err := app.storage.InsertAnonymousProfile(profile)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, model.TypeAnonymousProfile, nil, err)
	}
	return organization, nil
}

func (app *application) updateAnonymousProfile(l *logs.Log, id string, favorites *[]string, interests *[]string,
	negativeInterestTags *[]string, positiveInterestTags *[]string, privacySettings *string, over13 *bool) error {
	err := app.storage.UpdateAnonymousProfile(id, favorites, interests, negativeInterestTags, positiveInterestTags, privacySettings, over13)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAnonymousProfile, nil, err)
	}
	return nil
}

func (app *application) getAnonymousProfile(l *logs.Log, id string) (*model.AnonymousProfile, error) {
	profile, err := app.storage.FindAnonymousProfile(id)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeAnonymousProfile, nil, err)
	}
	return profile, nil
}

func (app *application) deleteAnonymousProfile(l *logs.Log, id string) error {
	err := app.storage.DeleteAnonymousProfile(id)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAnonymousProfile, nil, err)
	}
	return nil
}
