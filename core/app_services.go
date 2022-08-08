// Copyright 2022 Board of Trustees of the University of Illinois.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
	err = app.storage.UpdateProfile(nil, profile)
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

func (app *application) serGetAccounts(limit int, offset int, appID string, orgID string, accountID *string, firstName *string, lastName *string, authType *string,
	authTypeIdentifier *string, hasPermissions *bool, permissions []string, roleIDs []string, groupIDs []string) ([]model.Account, error) {
	//find the accounts
	accounts, err := app.storage.FindAccounts(limit, offset, appID, orgID, accountID, firstName, lastName, authType, authTypeIdentifier, hasPermissions, permissions, roleIDs, groupIDs)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	return accounts, nil
}

func (app *application) serGetAuthTest(l *logs.Log) string {
	return "Services - Auth - test"
}

func (app *application) serGetCommonTest(l *logs.Log) string {
	return "Services - Common - test"
}

func (app *application) serGetAppConfig(appTypeIdentifier string, appID *string, orgID *string, versionNumbers model.VersionNumbers, apiKey *string) (*model.ApplicationConfig, error) {
	var appTypeID string
	var err error
	if appID == nil || *appID == "" {
		//get the app type
		applicationType, err := app.storage.FindApplicationType(appTypeIdentifier)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationType, logutils.StringArgs(appTypeIdentifier), err)
		}
		if applicationType == nil {
			return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationType, logutils.StringArgs(appTypeIdentifier))
		}

		appID = &applicationType.Application.ID
		appTypeID = applicationType.ID
	}

	if appID == nil {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeApplicationID, nil, err)
	}

	if orgID == nil {
		if apiKey != nil {
			err := app.auth.ValidateAPIKey(*appID, *apiKey)
			if err != nil {
				return nil, errors.WrapErrorData(logutils.StatusInvalid, model.TypeAPIKey, nil, err)
			}
		} else {
			return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeOrganizationID, nil, err)
		}
	}

	var appOrgID *string
	if orgID != nil {
		appOrg, err := app.storage.FindApplicationOrganization(*appID, *orgID)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": appID, "org_id": *orgID}, err)
		}
		appOrgID = &appOrg.ID
	}

	// will return the patchAppConfig with greatest verion less than or equal to the versionNumbers provided
	_, patchAppConfigs, err := app.storage.FindAppConfigByVersion(*appID, appTypeID, appOrgID, versionNumbers)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationConfig, nil, err)
	}

	if len(patchAppConfigs) > 0 {
		return &patchAppConfigs[0], nil
	}

	return nil, nil
}
