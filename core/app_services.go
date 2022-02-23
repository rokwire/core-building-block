package core

import (
	"core-building-block/core/model"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

func (app *application) serGetProfile(accountID string) (*model.Profile, error) {
	//find the account
	account, err := app.storage.FindAccountByID(nil, accountID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}

	//get the profile for the account
	profile := account.Profile
	return &profile, nil
}

func (app *application) serGetAccount(accountID string) (*model.Account, error) {
	return app.getAccount(accountID)
}

func (app *application) serGetPreferences(accountID string) (map[string]interface{}, error) {
	//find the account
	account, err := app.storage.FindAccountByID(nil, accountID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountPreferences, nil, err)
	}
	if account == nil {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeAccountPreferences, nil, err)
	}

	preferences := account.Preferences
	return preferences, nil
}

func (app *application) serUpdateProfile(accountID string, profile model.Profile) error {
	//1. find the account
	account, err := app.storage.FindAccountByID(nil, accountID)
	if err != nil {
		return errors.Wrapf("error finding an account on profile update", err)
	}

	//2. get the profile ID from the account
	profile.ID = account.Profile.ID

	//3. update profile
	err = app.storage.UpdateProfile(profile)
	if err != nil {
		return errors.Wrapf("error updating a profile", err)
	}
	return nil
}

func (app *application) serUpdateAccountPreferences(id string, preferences map[string]interface{}) error {
	err := app.storage.UpdateAccountPreferences(id, preferences)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, nil, err)
	}
	return nil
}

func (app *application) serDeleteAccount(id string) error {
	return app.auth.DeleteAccount(id)
}

func (app *application) serGetAuthTest(l *logs.Log) string {
	return "Services - Auth - test"
}

func (app *application) serGetCommonTest(l *logs.Log) string {
	return "Services - Common - test"
}

func (app *application) serGetAppConfig(appTypeIdentifier string, orgID *string, versionNumbers model.VersionNumbers, apiKey *string) (*model.ApplicationConfig, error) {
	//get the app type
	applicationType, err := app.storage.FindApplicationType(appTypeIdentifier)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationType, logutils.StringArgs(appTypeIdentifier), err)
	}
	if applicationType == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationType, logutils.StringArgs(appTypeIdentifier))
	}

	appID := applicationType.Application.ID

	if orgID == nil || apiKey != nil {
		err = app.auth.ValidateAPIKey(appID, *apiKey)
		if err != nil {
			return nil, errors.WrapErrorData(logutils.StatusInvalid, model.TypeAPIKey, nil, err)
		}
	}

	var appOrgID *string
	if orgID != nil {
		appOrg, err := app.storage.FindApplicationOrganization(appID, *orgID)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": appID, "org_id": *orgID}, err)
		}
		appOrgID = &appOrg.ID
	}

	appConfigs, err := app.storage.FindAppConfigByVersion(applicationType.ID, appOrgID, versionNumbers)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationConfig, nil, err)
	}

	if appConfigs == nil {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeApplicationConfig, nil, err)
	}

	return appConfigs, nil
}
