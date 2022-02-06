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

		//3. remove account auth types from or delete credentials
		for _, aat := range account.AuthTypes {
			if aat.Credential != nil {
				credential, err := app.storage.FindCredential(context, aat.Credential.ID)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionFind, model.TypeCredential, nil, err)
				}

				if len(credential.AccountsAuthTypes) > 1 {
					now := time.Now().UTC()
					for i, credAat := range credential.AccountsAuthTypes {
						if credAat.ID == aat.ID {
							credential.AccountsAuthTypes = append(credential.AccountsAuthTypes[:i], credential.AccountsAuthTypes[i+1:]...)
							credential.DateUpdated = &now
							err = app.storage.UpdateCredential(context, credential)
							if err != nil {
								return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeCredential, nil, err)
							}
							break
						}
					}
				} else {
					err = app.storage.DeleteCredential(context, credential.ID)
					if err != nil {
						return errors.WrapErrorAction(logutils.ActionDelete, model.TypeCredential, nil, err)
					}
				}
			}
		}

		//4. delete login sessions
		err = app.storage.DeleteLoginSessionsByIdentifier(context, id)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionDelete, model.TypeLoginSession, nil, err)
		}

		//5. delete devices records
		for _, device := range account.Devices {
			err = app.storage.DeleteDevice(context, device.ID)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionDelete, model.TypeDevice, nil, err)
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
