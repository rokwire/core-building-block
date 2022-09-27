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

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
)

func (app *application) sharedGetAccount(accountID string) (*model.Account, error) {
	//find the account
	account, err := app.storage.FindAccountByID(nil, accountID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	if account == nil {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeAccount, nil, err)
	}
	return account, nil
}

func (app *application) sharedUpdateAccountUsername(accountID string, appID string, orgID string, username string) error {
	if username == "" {
		err := app.storage.UpdateAccountUsername(nil, accountID, username)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountUsername, nil, err)
		}

		return nil
	}

	transaction := func(context storage.TransactionContext) error {
		//1. find the app/org
		appOrg, err := app.storage.FindApplicationOrganization(appID, orgID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": appID, "org_id": orgID}, err)
		}
		if appOrg == nil {
			return errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": appID, "org_id": orgID})
		}

		//2. check if any accounts in the app/org use the username
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
			return errors.ErrorData(logutils.StatusInvalid, model.TypeAccountUsername, logutils.StringArgs(username+" taken"))
		}

		//3. update the username
		err = app.storage.UpdateAccountUsername(context, accountID, username)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAccountUsername, nil, err)
		}

		return nil
	}

	return app.storage.PerformTransaction(transaction)
}
