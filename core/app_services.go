package core

import (
	"core-building-block/core/model"
	"core-building-block/driven/storage"
	"time"

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

func (app *application) serUpdateProfile(accountID string, profile *model.Profile) error {
	return app.storage.UpdateProfile(accountID, profile)
}

func (app *application) serUpdateAccountPreferences(id string, preferences map[string]interface{}) error {
	err := app.storage.UpdateAccountPreferences(id, preferences)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, nil, err)
	}
	return nil
}

func (app *application) serDeleteAccount(id string) error {
	transaction := func(context storage.TransactionContext) error {
		//1. first find the account record
		account, err := app.storage.FindAccountByID(context, id)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
		}
		if account == nil {
			return errors.ErrorData(logutils.StatusMissing, model.TypeAccount, nil)
		}

		//2. delete the account record
		err = app.storage.DeleteAccount(context, id)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAccount, nil, err)
		}

		//3. save or delete device records
		for _, device := range account.Devices {
			if len(device.Accounts) > 1 {
				for i, deviceAccount := range device.Accounts {
					if deviceAccount.ID == id {
						device.Accounts = append(device.Accounts[:i], device.Accounts[i+1:]...)
						break
					}
				}
				*device.DateUpdated = time.Now().UTC()

				err = app.storage.SaveDevice(context, &device)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionSave, model.TypeDevice, nil, err)
				}
			} else {
				err = app.storage.DeleteDevice(context, device.ID)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionDelete, model.TypeDevice, nil, err)
				}
			}
		}

		return nil
	}

	return app.storage.PerformTransaction(transaction)
}

func (app *application) serGetAuthTest(l *logs.Log) string {
	return "Services - Auth - test"
}

func (app *application) serGetCommonTest(l *logs.Log) string {
	return "Services - Common - test"
}

func (app *application) serGetAppConfigs(appID string, versionNumbers map[string]string) ([]model.ApplicationConfigs, error) {
	appConfigs, err := app.storage.FindAppConfigs(appID, versionNumbers)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationConfigs, nil, err)
	}

	return appConfigs, nil
}
