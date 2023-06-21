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
	"core-building-block/driven/storage"

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logs"
	"github.com/rokwire/logging-library-go/v2/logutils"
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
	return app.getAccount(nil, accountID)
}

func (app *application) serGetPreferences(accountID string) (map[string]interface{}, error) {
	//find the account
	account, err := app.storage.FindAccountByID(nil, accountID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountPreferences, &logutils.FieldArgs{"account_id": accountID}, err)
	}
	if account == nil {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeAccountPreferences, &logutils.FieldArgs{"account_id": accountID}, err)
	}

	preferences := account.Preferences
	return preferences, nil
}

func (app *application) serGetAccountSystemConfigs(accountID string) (map[string]interface{}, error) {
	//find the account
	account, err := app.storage.FindAccountByID(nil, accountID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountSystemConfigs, &logutils.FieldArgs{"account_id": accountID}, err)
	}
	if account == nil {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeAccountSystemConfigs, &logutils.FieldArgs{"account_id": accountID}, err)
	}

	return account.SystemConfigs, nil
}

func (app *application) serUpdateAccountProfile(accountID string, profile model.Profile) error {
	//1. find the account
	account, err := app.storage.FindAccountByID(nil, accountID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}

	//2. get the profile ID from the account
	profile.ID = account.Profile.ID

	//3. update profile
	err = app.storage.UpdateAccountProfile(nil, profile)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeProfile, nil, err)
	}
	return nil
}

func (app *application) serUpdateAccountPrivacy(accountID string, privacy model.Privacy) error {
	//1. find the account
	account, err := app.storage.FindAccountByID(nil, accountID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypePrivacy, nil, err)
	}

	//2. get the privacy ID from the account
	privacy.ID = account.Privacy.ID

	//3. update privacy
	err = app.storage.UpdateAccountPrivacy(nil, privacy)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypePrivacy, nil, err)
	}
	return nil
}

func (app *application) serUpdateAccountPreferences(id string, appID string, orgID string, anonymous bool, preferences map[string]interface{}, l *logs.Log) (bool, error) {
	if anonymous {
		created := false
		transaction := func(context storage.TransactionContext) error {
			//1. verify that the account is for the current app/org
			account, err := app.storage.FindAccountByID(context, id)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccountSystemConfigs, &logutils.FieldArgs{"account_id": id}, err)
			}
			if account == nil {
				created = true
				_, err = app.auth.CreateAnonymousAccount(context, appID, orgID, id, preferences, nil, true, l)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionCreate, model.TypeAccount, nil, err)
				}
				return nil
			}
			err = app.storage.UpdateAccountPreferences(context, id, preferences)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountPreferences, nil, err)
			}
			return nil
		}

		err := app.storage.PerformTransaction(transaction)
		if err != nil {
			return false, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccount, nil, err)
		}
		return created, nil
	}

	err := app.storage.UpdateAccountPreferences(nil, id, preferences)
	if err != nil {
		return false, errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountPreferences, nil, err)
	}
	return false, nil
}

func (app *application) serDeleteAccount(id string) error {
	return app.auth.DeleteAccount(id)
}

func (app *application) serGetAccounts(limit int, offset int, appID string, orgID string, accountID *string, firstName *string, lastName *string, authType *string,
	authTypeIdentifier *string, anonymous *bool, hasPermissions *bool, permissions []string, roleIDs []string, groupIDs []string) ([]model.Account, error) {
	//find the accounts
	accounts, err := app.storage.FindAccounts(nil, &limit, &offset, appID, orgID, accountID, firstName, lastName, authType, authTypeIdentifier, anonymous, hasPermissions, permissions, roleIDs, groupIDs)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	return accounts, nil
}

func (app *application) serGetPublicAccounts(appID string, orgID string, limit int, offset int, firstName *string, lastName *string, username *string) ([]model.PublicAccount, error) {
	//find the accounts
	accounts, err := app.storage.FindPublicAccounts(nil, appID, orgID, &limit, &offset, firstName, lastName, username)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	return accounts, nil
}

func (app *application) serAddFollow(follow model.Follow) error {
	err := app.storage.InsertFollow(nil, follow)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionInsert, model.TypeFollow, nil, err)
	}
	return nil
}

func (app *application) serDeleteFollow(appID string, orgID string, FolloweeID string, userID string) error {
	err := app.storage.DeleteFollow(nil, appID, orgID, FolloweeID, userID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeFollow, nil, err)
	}
	return nil
}

func (app *application) serGetFollows(appID string, orgID string, limit *int, offset *int, followeeID string, userID string) ([]model.PublicAccount, error) {
	follows, err := app.storage.FindFollows(nil, appID, orgID, limit, offset, followeeID, userID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	return follows, nil
}

func (app *application) serGetAuthTest(l *logs.Log) string {
	return "Services - Auth - test"
}

func (app *application) serGetCommonTest(l *logs.Log) string {
	return "Services - Common - test"
}

func (app *application) serGetAppConfig(appTypeIdentifier string, orgID *string, versionNumbers model.VersionNumbers, apiKey *string) (*model.ApplicationConfig, error) {
	return app.sharedGetAppConfig(appTypeIdentifier, orgID, versionNumbers, apiKey, false)
}
