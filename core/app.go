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

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

//application represents the core application code based on hexagonal architecture
type application struct {
	env     string
	version string
	build   string

	storage Storage

	listeners       []ApplicationListener
	requestExecutor HTTPRequestExecutor

	auth auth.APIs
}

//start starts the core part of the application
func (app *application) start() {
	//set storage listener
	storageListener := StorageListener{app: app}
	app.storage.RegisterStorageListener(&storageListener)
}

//addListener adds application listener
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

func (app *application) getAccount(accountID string) (*model.Account, error) {
	//find the account
	account, err := app.storage.FindAccountByID(nil, accountID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	return account, nil
}

//checkPermissions checks if the provided permissions ids are valid for the app/org.
//	it returns the permissions list for these ids if they are valid
func (app *application) checkPermissions(appOrg model.ApplicationOrganization, permissionIDs []string, l *logs.Log) ([]model.Permission, error) {
	if len(permissionIDs) == 0 {
		return nil, nil
	}

	permissions, err := app.storage.FindPermissionsByServiceIDs(appOrg.ServicesIDs)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypePermission, nil, err)
	}
	if len(permissionIDs) > len(permissions) {
		return nil, errors.New("mismatch permissions count")
	}
	rolePermissions := make([]model.Permission, len(permissionIDs))
	for i, permissionID := range permissionIDs {
		var rolePermission *model.Permission

		for _, permission := range permissions {
			if permission.ID == permissionID {
				rolePermission = &permission
				break
			}
		}

		if rolePermission == nil {
			l.Infof("%s permission does not match", permissionID)
			return nil, errors.Newf("%s permission does not match", permissionID)
		}
		rolePermissions[i] = *rolePermission
	}
	return rolePermissions, nil
}

//checkRoles checkRoles if the provided roles ids are valid for the app/org.
//	it returns the roles list for these ids if they are valid
func (app *application) checkRoles(appOrg model.ApplicationOrganization, rolesIDs []string, l *logs.Log) ([]model.AppOrgRole, error) {
	if len(rolesIDs) == 0 {
		return nil, nil
	}

	appOrgRoles, err := app.storage.FindAppOrgRolesByIDs(nil, rolesIDs, appOrg.ID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAppOrgRole, nil, err)
	}

	if len(rolesIDs) != len(appOrgRoles) {
		return nil, errors.New("mismatch roles count")
	}

	return appOrgRoles, nil
}
