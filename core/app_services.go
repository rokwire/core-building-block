package core

import (
	"core-building-block/core/model"

	log "github.com/rokmetro/logging-library/loglib"
)

func (app *application) serGetAuthTest(l *log.Log) string {
	return "Services - Auth - test"
}

func (app *application) serGetCommonTest(l *log.Log) string {
	return "Services - Common - test"
}

func (app *application) createAnonymousProfile(l *log.Log, profile *model.AnonymousProfile) (*model.AnonymousProfile, error) {
	organization, err := app.storage.CreateAnonymousProfile(profile)
	if err != nil {
		return nil, log.WrapErrorAction(log.ActionCreate, model.TypeAnonymousProfile, nil, err)
	}
	return organization, nil
}

func (app *application) updateAnonymousProfile(l *log.Log, id string, favorites *[]string, interests *[]string,
	negativeInterestTags *[]string, positiveInterestTags *[]string, privacySettings *string, over13 *bool) error {
	err := app.storage.UpdateAnonymousProfile(id, favorites, interests, negativeInterestTags, positiveInterestTags, privacySettings, over13)
	if err != nil {
		return log.WrapErrorAction(log.ActionUpdate, model.TypeAnonymousProfile, nil, err)
	}
	return nil
}

func (app *application) getAnonymousProfile(l *log.Log, id string) (*model.AnonymousProfile, error) {
	profile, err := app.storage.GetAnonymousProfile(id)
	if err != nil {
		return nil, log.WrapErrorAction(log.ActionGet, model.TypeAnonymousProfile, nil, err)
	}
	return profile, nil
}

func (app *application) deleteAnonymousProfile(l *log.Log, id string) error {
	err := app.storage.DeleteAnonymousProfile(id)
	if err != nil {
		return log.WrapErrorAction(log.ActionDelete, model.TypeAnonymousProfile, nil, err)
	}
	return nil
}
