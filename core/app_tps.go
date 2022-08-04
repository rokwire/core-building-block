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
	"time"

	"github.com/google/uuid"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
)

func (app *application) tpsGetTest() string {
	return "TPs - test"
}

func (app *application) tpsUpdatePermissions(permissions []model.Permission, accountID string) ([]model.Permission, error) {
	//find the service registration record
	serviceReg, err := app.storage.FindServiceRegByServiceAccountID(accountID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeServiceAccount, nil, err)
	}
	if serviceReg == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeServiceReg, &logutils.FieldArgs{"service_account_id": accountID})
	}

	servicePermissions := make([]model.Permission, 0)
	transaction := func(context storage.TransactionContext) error {
		newNames := make([]string, len(permissions))
		newNamesMap := make(map[string]model.Permission)
		allAssigners := make([]string, 0)
		for i, p := range permissions {
			newNames[i] = p.Name
			newNamesMap[p.Name] = p
			allAssigners = append(allAssigners, p.Assigners...)
		}

		//1. check if any incoming permissions have the same name as another service's permission
		invalidNames := make(map[string][]string)
		existingPermissions, err := app.storage.FindPermissionsByName(context, newNames)
		if err != nil {
			return err
		}
		for _, p := range existingPermissions {
			if p.ServiceID != serviceReg.Registration.ServiceID {
				if invalidNames[p.ServiceID] == nil {
					invalidNames[p.ServiceID] = []string{}
				}
				invalidNames[p.ServiceID] = append(invalidNames[p.ServiceID], p.Name)
			}
		}
		if len(invalidNames) > 0 {
			return errors.ErrorData(logutils.StatusInvalid, model.TypePermission, &logutils.FieldArgs{"names": invalidNames})
		}

		//2. get the list of existing assigner permissions from the incoming permission list
		existingAssigners, err := app.storage.FindPermissionsByName(context, allAssigners)
		if err != nil {
			return err
		}

		//3. get current list of service permissions
		serviceIDs := []string{serviceReg.Registration.ServiceID}
		currentPermissions, err := app.storage.FindPermissionsByServiceIDs(context, serviceIDs)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypePermission, &logutils.FieldArgs{"service_id": serviceReg.Registration.ServiceID}, err)
		}

		currentNames := make([]string, len(currentPermissions))
		currentNamesMap := make(map[string]model.Permission)
		for i, p := range currentPermissions {
			currentNames[i] = p.Name
			currentNamesMap[p.Name] = p
		}

		now := time.Now().UTC()
		added, removed, unchanged := utils.StringListDiff(newNames, currentNames)

		//4. if added, create a new permission
		for _, name := range added {
			permission := newNamesMap[name]
			err = model.CheckPermissionsExist(permission.Assigners, existingAssigners, permissions)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionValidate, "assigners", nil, err)
			}

			permission.ID = uuid.NewString()
			permission.ServiceID = serviceReg.Registration.ServiceID
			permission.Inactive = false
			permission.DateCreated = now
			servicePermissions = append(servicePermissions, permission)
		}
		err = app.storage.InsertPermissions(context, servicePermissions)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionInsert, model.TypePermission, &logutils.FieldArgs{"name": added}, err)
		}

		//5. if removed, mark existing permission as inactive
		for _, name := range removed {
			permission := currentNamesMap[name]
			if !permission.Inactive {
				permission.Inactive = true
				permission.DateUpdated = &now
				err = app.storage.UpdatePermission(context, permission)
				if err != nil {
					return errors.WrapErrorAction(logutils.ActionUpdate, model.TypePermission, &logutils.FieldArgs{"name": name}, err)
				}
			}
		}

		//6. if unchanged, update permission data if necessary
		for _, name := range unchanged {
			currentPermission := currentNamesMap[name]
			newPermission := newNamesMap[name]
			err = model.CheckPermissionsExist(newPermission.Assigners, existingAssigners, permissions)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionValidate, "assigners", nil, err)
			}

			description := newPermission.Description
			assigners := newPermission.Assigners
			updated := currentPermission.Inactive || (description != currentPermission.Description) || !utils.DeepEqual(assigners, currentPermission.Assigners)
			newPermission = currentPermission
			if updated {
				newPermission.Description = description
				newPermission.Assigners = assigners
				newPermission.Inactive = false
				newPermission.DateUpdated = &now
				err = app.storage.UpdatePermission(context, newPermission)
				if err != nil {
					return err
				}
			}

			servicePermissions = append(servicePermissions, newPermission)
		}

		return nil
	}

	err = app.storage.PerformTransaction(transaction)
	if err != nil {
		return nil, err
	}

	return servicePermissions, nil
}
