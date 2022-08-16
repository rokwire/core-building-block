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
	"core-building-block/core/auth"
	"core-building-block/core/model"
	"core-building-block/driven/storage"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
)

// application represents the core application code based on hexagonal architecture
type application struct {
	env     string
	version string
	build   string

	storage Storage

	listeners []ApplicationListener

	auth auth.APIs
}

// start starts the core part of the application
func (app *application) start() {
	//set storage listener
	storageListener := StorageListener{app: app}
	app.storage.RegisterStorageListener(&storageListener)
}

// addListener adds application listener
func (app *application) addListener(listener ApplicationListener) {
	//TODO
	//logs.Println("Application -> AddListener")

	app.listeners = append(app.listeners, listener)
}

func (app *application) notifyListeners(message string, data interface{}) {
	go func() {
		// TODO
	}()
}

func (app *application) getAccount(context storage.TransactionContext, accountID string) (*model.Account, error) {
	//find the account
	account, err := app.storage.FindAccountByID(context, accountID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, &logutils.FieldArgs{"id": accountID}, err)
	}
	if account == nil {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeAccount, &logutils.FieldArgs{"id": accountID}, err)
	}

	return account, nil
}

func (app *application) getApplicationOrganization(appID string, orgID string) (*model.ApplicationOrganization, error) {
	appOrg, err := app.storage.FindApplicationOrganization(appID, orgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeApplicationOrganization, nil, err)
	}
	if appOrg == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": appID, "org_id": orgID})
	}

	return appOrg, nil
}

func (app *application) getAppOrgRole(context storage.TransactionContext, id string, appOrgID string, systemAdmin bool) (*model.AppOrgRole, error) {
	role, err := app.storage.FindAppOrgRole(context, id, appOrgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAppOrgRole, &logutils.FieldArgs{"id": id}, err)
	}
	if role == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeAppOrgRole, &logutils.FieldArgs{"id": id})
	}
	if role.System && !systemAdmin {
		return nil, errors.ErrorData(logutils.StatusInvalid, logutils.TypeClaim, logutils.StringArgs("system"))
	}

	return role, nil
}
