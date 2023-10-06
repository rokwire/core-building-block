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
	"core-building-block/utils"

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

func (app *application) sharedGetAppConfig(appTypeIdentifier string, orgID *string, versionNumbers model.VersionNumbers, apiKey *string, admin bool) (*model.ApplicationConfig, error) {
	//get the app type
	applicationType, err := app.storage.FindApplicationType(appTypeIdentifier)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationType, logutils.StringArgs(appTypeIdentifier), err)
	}
	if applicationType == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationType, logutils.StringArgs(appTypeIdentifier))
	}

	if !admin && applicationType.Application.Admin {
		return nil, errors.ErrorData(logutils.StatusInvalid, logutils.TypeClaim, logutils.StringArgs("admin"))
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

func (app *application) sharedGetAccountsByParams(searchParams map[string]interface{}, appID string, orgID string, limit int, offset int, allAccess bool, approvedKeys []string) ([]map[string]interface{}, error) {
	accounts, err := app.storage.FindAccountsByParams(searchParams, appID, orgID, limit, offset, allAccess, approvedKeys)
	if err != nil {
		return nil, err
	}
	if accounts == nil {
		return []map[string]interface{}{}, nil
	}
	return accounts, nil
}

func (app *application) sharedGetAccountsCountByParams(searchParams map[string]interface{}, appID string, orgID string) (int64, error) {
	count, err := app.storage.CountAccountsByParams(searchParams, appID, orgID)
	if err != nil {
		return -1, err
	}

	return count, nil
}

func (app *application) sharedUpdateAccountUsername(accountID string, appID string, orgID string, username string) error {
	if username == "" {
		return errors.ErrorData(logutils.StatusMissing, model.TypeAccountUsername, nil)
	}

	appOrg, err := app.storage.FindApplicationOrganization(appID, orgID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": appID, "org_id": orgID}, err)
	}
	if appOrg == nil {
		return errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": appID, "org_id": orgID})
	}

	transaction := func(context storage.TransactionContext) error {
		//1. check if any accounts in the app/org use the username
		accounts, err := app.storage.FindAccountsByUsername(context, appOrg, username)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
		}
		if len(accounts) > 0 {
			for _, account := range accounts {
				//skip update if account already has the requested username
				if account.ID == accountID {
					return nil
				}
			}
			return errors.ErrorData(logutils.StatusInvalid, model.TypeAccountUsername, logutils.StringArgs(username+" taken")).SetStatus(utils.ErrorStatusUsernameTaken)
		}

		//2. update the username
		err = app.storage.UpdateAccountUsername(context, accountID, username)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountUsername, nil, err)
		}

		return nil
	}

	return app.storage.PerformTransaction(transaction)
}
