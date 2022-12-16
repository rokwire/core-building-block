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
	"core-building-block/core/interfaces"
	"core-building-block/core/model"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
)

func (app *application) sharedGetAccount(accountID string) (*model.Account, error) {
	//find the account
	account, err := app.storage.FindAccountByID(accountID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	if account == nil {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeAccount, nil, err)
	}
	return account, nil
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
		err := app.storage.UpdateAccountUsername(accountID, username)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountUsername, nil, err)
		}

		return nil
	}

	transaction := func(storage interfaces.Storage) error {
		//1. find the app/org
		appOrg, err := storage.FindApplicationOrganization(appID, orgID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": appID, "org_id": orgID}, err)
		}
		if appOrg == nil {
			return errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": appID, "org_id": orgID})
		}

		//2. check if any accounts in the app/org use the username
		accounts, err := storage.FindAccountsByUsername(appOrg, username)
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
			return errors.ErrorData(logutils.StatusInvalid, model.TypeAccountUsername, logutils.StringArgs(username+" taken"))
		}

		//3. update the username
		err = storage.UpdateAccountUsername(accountID, username)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountUsername, nil, err)
		}

		return nil
	}

	return app.storage.PerformTransaction(transaction)
}
