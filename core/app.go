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
	"core-building-block/utils"
	"time"

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
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
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	if account == nil {
		return nil, errors.WrapErrorData(logutils.StatusMissing, model.TypeAccount, nil, err)
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

func (app *application) getAppOrgGroup(context storage.TransactionContext, id string, appOrgID string, systemAdmin *bool) (*model.AppOrgGroup, error) {
	group, err := app.storage.FindAppOrgGroup(context, id, appOrgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAppOrgGroup, &logutils.FieldArgs{"id": id}, err)
	}
	if group == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeAppOrgGroup, &logutils.FieldArgs{"id": id})
	}
	if systemAdmin != nil && group.System && !*systemAdmin {
		return nil, errors.ErrorData(logutils.StatusInvalid, logutils.TypeClaim, logutils.StringArgs("system"))
	}

	return group, nil
}

// grantOrRevokePermissions grants or revokes permissions after validating the assigner has required permissions
//
//	Expects container to be pointer to type implementing model.PermissionContainer
func (app *application) grantOrRevokePermissions(context storage.TransactionContext, container model.PermissionContainer, permissionNames []string, assignerPermissions []string, revoke bool) error {
	if container == nil {
		return errors.ErrorData(logutils.StatusMissing, "permissions container", nil)
	}

	//only grant permissions container does not have, revoke permissions container does have
	checkPermissions := make([]string, 0)
	for _, current := range permissionNames {
		hasP := container.GetPermissionNamed(current) != nil
		if revoke == hasP {
			checkPermissions = append(checkPermissions, current)
		}
	}
	//no error if no permissions to grant or revoke
	if len(checkPermissions) == 0 {
		return nil
	}

	appOrg := container.GetAppOrg()
	//check permissions
	permissions, err := app.auth.CheckPermissions(context, []model.ApplicationOrganization{appOrg}, checkPermissions, assignerPermissions, revoke)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionValidate, model.TypePermission, nil, err)
	}

	switch c := container.(type) {
	case *model.Account:
		{
			if revoke {
				//delete permissions from an account
				err = app.storage.DeleteAccountPermissions(context, c.ID, checkPermissions)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAccountPermissions, &logutils.FieldArgs{"names": checkPermissions}, err)
				}

				//delete all sessions for the account
				err = app.storage.DeleteLoginSessionsByIdentifier(context, c.ID)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionDelete, model.TypeLoginSession, nil, err)
				}
			} else {
				//add permissions to account
				err = app.storage.InsertAccountPermissions(context, c.ID, permissions)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionInsert, model.TypeAccountPermissions, &logutils.FieldArgs{"names": checkPermissions}, err)
				}
			}
		}
	case *model.AppOrgRole:
		{
			if revoke {
				newPermissions := make([]model.Permission, 0)
				for _, p := range c.Permissions {
					if !utils.Contains(checkPermissions, p.Name) {
						newPermissions = append(newPermissions, p)
					}
				}
				c.Permissions = newPermissions
			} else {
				c.Permissions = append(c.Permissions, permissions...)
			}

			//update role
			now := time.Now().UTC()
			c.DateUpdated = &now
			err = app.storage.UpdateAppOrgRole(context, *c)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAppOrgRole, nil, err)
			}
		}
	}

	return nil
}

// grantOrRevokeRoles grants or revokes roles after validating the assigner has required permissions
//
//	Expects container to be pointer to type implementing model.RoleContainer
func (app *application) grantOrRevokeRoles(context storage.TransactionContext, container model.RoleContainer, roleIDs []string, assignerPermissions []string, revoke bool) error {
	if container == nil {
		return errors.ErrorData(logutils.StatusMissing, "roles container", nil)
	}

	//only grant roles container does not have, revoke roles container does have
	checkRoles := make([]string, 0)
	for _, current := range roleIDs {
		hasR := container.GetRole(current) != nil
		if revoke == hasR {
			checkRoles = append(checkRoles, current)
		}
	}
	//no error if no roles to grant or revoke
	if len(checkRoles) == 0 {
		return nil
	}

	appOrg := container.GetAppOrg()
	//check roles
	roles, err := app.auth.CheckRoles(context, &appOrg, checkRoles, assignerPermissions, revoke)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionValidate, model.TypeAppOrgRole, nil, err)
	}

	switch c := container.(type) {
	case *model.Account:
		{
			if revoke {
				//delete roles from an account
				err = app.storage.DeleteAccountRoles(context, c.ID, checkRoles)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionDelete, model.TypeAccountRoles, &logutils.FieldArgs{"ids": checkRoles}, err)
				}

				//delete all sessions for the account
				err = app.storage.DeleteLoginSessionsByIdentifier(context, c.ID)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionDelete, model.TypeLoginSession, nil, err)
				}
			} else {
				//add roles to account
				accountRoles := model.AccountRolesFromAppOrgRoles(roles, true, true)
				err = app.storage.InsertAccountRoles(context, c.ID, c.AppOrg.ID, accountRoles)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionInsert, model.TypeAccountRoles, &logutils.FieldArgs{"ids": checkRoles}, err)
				}
			}
		}
	case *model.AppOrgGroup:
		{
			if revoke {
				newRoles := make([]model.AppOrgRole, 0)
				for _, r := range c.Roles {
					if !utils.Contains(checkRoles, r.ID) {
						newRoles = append(newRoles, r)
					}
				}
				c.Roles = newRoles
			} else {
				c.Roles = append(c.Roles, roles...)
			}

			//update role
			now := time.Now().UTC()
			c.DateUpdated = &now
			err = app.storage.UpdateAppOrgGroup(context, *c)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAppOrgGroup, nil, err)
			}
		}
	}

	return nil
}
