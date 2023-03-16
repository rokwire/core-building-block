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
	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

func (app *application) sysCreateGlobalConfig(setting string) (*model.GlobalConfig, error) {
	gc, err := app.storage.GetGlobalConfig()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeGlobalConfig, nil, err)
	}
	if gc != nil {
		return nil, errors.ErrorData("existing", model.TypeGlobalConfig, nil)
	}

	gc = &model.GlobalConfig{Setting: setting}
	err = app.storage.CreateGlobalConfig(nil, gc)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionInsert, model.TypeGlobalConfig, nil, err)
	}
	return gc, nil
}

func (app *application) sysGetGlobalConfig() (*model.GlobalConfig, error) {
	gc, err := app.storage.GetGlobalConfig()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeGlobalConfig, nil, err)
	}
	return gc, nil
}

func (app *application) sysUpdateGlobalConfig(setting string) error {
	gc, err := app.storage.GetGlobalConfig()
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeGlobalConfig, nil, err)
	}
	if gc == nil {
		return errors.WrapErrorData(logutils.StatusMissing, model.TypeGlobalConfig, nil, err)
	}

	gc.Setting = setting
	transaction := func(context storage.TransactionContext) error {
		//1. clear the global config - we always keep only one global config
		err := app.storage.DeleteGlobalConfig(context)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionDelete, model.TypeGlobalConfig, nil, err)
		}

		//2. add the new one
		err = app.storage.CreateGlobalConfig(context, gc)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionInsert, model.TypeGlobalConfig, nil, err)
		}

		return nil
	}

	return app.storage.PerformTransaction(transaction)
}

func (app *application) sysGetApplicationOrganizations(appID *string, orgID *string) ([]model.ApplicationOrganization, error) {
	return app.storage.FindApplicationOrganizations(appID, orgID)
}

func (app *application) sysGetApplicationOrganization(ID string) (*model.ApplicationOrganization, error) {
	return app.storage.FindApplicationOrganizationByID(ID)
}

func (app *application) sysCreateApplicationOrganization(appOrg model.ApplicationOrganization) error {
	application, err := app.storage.FindApplication(nil, appOrg.Application.ID)
	if err != nil || application == nil {
		return errors.WrapErrorData(logutils.StatusInvalid, model.TypeApplication, nil, err)
	}
	appOrg.Application = *application

	// validate app type IDs
	for _, authType := range appOrg.AuthTypes {
		if authType.AppTypeConfigs != nil {
			for _, config := range authType.AppTypeConfigs.Overrides {
				if appTypeID := config.GetAppTypeID(); appTypeID == nil || application.FindApplicationType(*appTypeID) == nil {
					return errors.ErrorData(logutils.StatusInvalid, model.TypeApplicationType, &logutils.FieldArgs{"id": utils.GetPrintableString(appTypeID, "")})
				}
			}
		}
	}
	// validate login session settings app type IDs and auth type codes
	for _, lsSettings := range appOrg.LoginSessionSettings.Overrides {
		appTypeID := lsSettings.GetAppTypeID()
		if appTypeID != nil && application.FindApplicationType(*appTypeID) == nil {
			return errors.ErrorData(logutils.StatusInvalid, "login session settings application type", &logutils.FieldArgs{"id": *appTypeID})
		}

		authTypeCode := lsSettings.GetAuthTypeCode()
		if authTypeCode != nil {
			if _, authTypeExists := appOrg.AuthTypes[*authTypeCode]; !authTypeExists {
				return errors.ErrorData(logutils.StatusInvalid, "login session settings auth type", &logutils.FieldArgs{"code": *authTypeCode})
			}
		}
	}

	organization, err := app.storage.FindOrganization(appOrg.Organization.ID)
	if err != nil || organization == nil {
		return errors.WrapErrorData(logutils.StatusInvalid, model.TypeOrganization, nil, err)
	}
	appOrg.Organization = *organization

	appOrgID, _ := uuid.NewUUID()
	appOrg.ID = appOrgID.String()
	appOrg.DateCreated = time.Now()

	err = app.storage.InsertApplicationOrganization(nil, appOrg)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeOrganization, nil, err)
	}

	return nil
}

func (app *application) sysUpdateApplicationOrganization(appOrg model.ApplicationOrganization) error {
	application, err := app.storage.FindApplication(nil, appOrg.Application.ID)
	if err != nil || application == nil {
		return errors.WrapErrorData(logutils.StatusInvalid, model.TypeApplication, nil, err)
	}

	// validate app type IDs
	for _, authType := range appOrg.AuthTypes {
		if authType.AppTypeConfigs != nil {
			for _, config := range authType.AppTypeConfigs.Overrides {
				if appTypeID := config.GetAppTypeID(); appTypeID == nil || application.FindApplicationType(*appTypeID) == nil {
					return errors.ErrorData(logutils.StatusInvalid, model.TypeApplicationType, &logutils.FieldArgs{"id": utils.GetPrintableString(appTypeID, "")})
				}
			}
		}
	}
	// validate login session settings app type IDs and auth type codes
	for _, lsSettings := range appOrg.LoginSessionSettings.Overrides {
		appTypeID := lsSettings.GetAppTypeID()
		if appTypeID != nil && application.FindApplicationType(*appTypeID) == nil {
			return errors.ErrorData(logutils.StatusInvalid, "login session settings application type", &logutils.FieldArgs{"id": *appTypeID})
		}

		authTypeCode := lsSettings.GetAuthTypeCode()
		if authTypeCode != nil {
			if _, authTypeExists := appOrg.AuthTypes[*authTypeCode]; !authTypeExists {
				return errors.ErrorData(logutils.StatusInvalid, "login session settings auth type", &logutils.FieldArgs{"code": *authTypeCode})
			}
		}
	}

	err = app.storage.UpdateApplicationOrganization(nil, appOrg)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeApplicationOrganization, nil, err)
	}

	return err

}

func (app *application) sysCreateOrganization(name string, requestType string, organizationDomains []string) (*model.Organization, error) {
	now := time.Now()

	orgConfig := model.OrganizationConfig{ID: uuid.NewString(), Domains: organizationDomains, DateCreated: now}
	organization := model.Organization{ID: uuid.NewString(), Name: name, Type: requestType, Config: orgConfig, DateCreated: now}

	insertedOrg, err := app.storage.InsertOrganization(nil, organization)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeOrganization, nil, err)
	}
	return insertedOrg, nil
}

func (app *application) sysGetOrganization(ID string) (*model.Organization, error) {
	organization, err := app.storage.FindOrganization(ID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeOrganization, nil, err)
	}
	if organization == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeOrganization, nil)
	}

	return organization, nil
}

func (app *application) sysGetOrganizations() ([]model.Organization, error) {
	getOrganization, err := app.storage.FindOrganizations()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeOrganization, nil, err)
	}

	return getOrganization, nil
}

func (app *application) sysUpdateOrganization(ID string, name string, requestType string, organizationDomains []string) error {
	err := app.storage.UpdateOrganization(ID, name, requestType, organizationDomains)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeOrganization, nil, err)
	}

	return err

}

func (app *application) sysGetApplication(ID string) (*model.Application, error) {
	appAdm, err := app.storage.FindApplication(nil, ID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeApplication, nil, err)
	}
	if appAdm == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplication, nil)
	}

	return appAdm, nil
}

func (app *application) sysCreateApplication(name string, multiTenant bool, admin bool, sharedIdentities bool, appTypes []model.ApplicationType) (*model.Application, error) {
	now := time.Now()

	// application
	for i, at := range appTypes {
		appTypes[i].ID = uuid.NewString()
		appTypes[i].DateCreated = now
		for vidx := range at.Versions {
			appTypes[i].Versions[vidx].ID = uuid.NewString()
			appTypes[i].Versions[vidx].ApplicationType = model.ApplicationType{ID: appTypes[i].ID}
			appTypes[i].Versions[vidx].DateCreated = now
		}
	}
	application := model.Application{ID: uuid.NewString(), Name: name, MultiTenant: multiTenant, Admin: admin, SharedIdentities: sharedIdentities,
		Types: appTypes, DateCreated: now}

	insertedApplication, err := app.storage.InsertApplication(nil, application)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, model.TypeApplication, nil, err)
	}
	return insertedApplication, nil
}

func (app *application) sysUpdateApplication(ID string, name string, multiTenant bool, admin bool, sharedIdentities bool, appTypes []model.ApplicationType) error {
	transaction := func(context storage.TransactionContext) error {
		//1. find application
		application, err := app.storage.FindApplication(context, ID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeApplication, nil, err)
		}
		if application == nil {
			return errors.ErrorData(logutils.StatusMissing, model.TypeApplication, nil)
		}

		//2. update app type list
		updated := false
		now := time.Now().UTC()
		for i, at := range appTypes {
			existingAppType := application.FindApplicationType(at.Identifier)
			if existingAppType != nil {
				//unchanged app type identifier, so set existing ID
				appTypes[i].ID = existingAppType.ID
				appTypes[i].Versions = existingAppType.Versions
				appTypes[i].DateCreated = existingAppType.DateCreated
				if at.Name != existingAppType.Name {
					appTypes[i].DateUpdated = &now
					updated = true
				}
			} else {
				//added app type identifier, so set new ID
				appTypes[i].ID = uuid.NewString()
				for vidx := range at.Versions {
					appTypes[i].Versions[vidx].ID = uuid.NewString()
					appTypes[i].Versions[vidx].ApplicationType = model.ApplicationType{ID: appTypes[i].ID}
					appTypes[i].Versions[vidx].DateCreated = now
				}
				appTypes[i].DateCreated = now
				updated = true
			}
		}

		//3. update if app types or other application params were updated
		updated = updated || (name != application.Name) || (multiTenant != application.MultiTenant) || (admin != application.Admin) || (sharedIdentities != application.SharedIdentities)
		if updated {
			updatedApp := model.Application{ID: application.ID, Name: name, MultiTenant: multiTenant, Admin: admin, SharedIdentities: sharedIdentities,
				Types: appTypes, DateCreated: application.DateCreated, DateUpdated: &now}
			err = app.storage.SaveApplication(context, updatedApp)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionSave, model.TypeApplication, nil, err)
			}
		}

		return nil
	}

	return app.storage.PerformTransaction(transaction)
}

func (app *application) sysGetApplications() ([]model.Application, error) {
	getApplications, err := app.storage.FindApplications()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeApplication, nil, err)
	}

	return getApplications, nil
}

func (app *application) sysCreatePermission(name string, description *string, serviceID *string, assigners *[]string) (*model.Permission, error) {
	id, _ := uuid.NewUUID()
	now := time.Now()
	serviceIDVal := ""
	if serviceID != nil {
		serviceIDVal = *serviceID
	}
	descriptionVal := ""
	if description != nil {
		descriptionVal = *description
	}

	permission := model.Permission{ID: id.String(), Name: name, Description: descriptionVal, DateCreated: now, ServiceID: serviceIDVal, Assigners: *assigners}

	err := app.storage.InsertPermission(nil, permission)

	if err != nil {
		return nil, err
	}
	return &permission, nil
}

func (app *application) sysUpdatePermission(name string, description *string, serviceID *string, assigners *[]string) (*model.Permission, error) {
	permissionNames := []string{name}
	permissions, err := app.storage.FindPermissionsByName(nil, permissionNames)
	if err != nil {
		return nil, err
	}
	if permissions == nil || len(permissions) < 1 {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypePermission, nil, err)
	}

	permission := permissions[0]
	if description != nil {
		permission.Description = *description
	}
	if serviceID != nil {
		permission.ServiceID = *serviceID
	}
	if assigners != nil {
		permission.Assigners = *assigners
	}

	err = app.storage.UpdatePermission(permission)
	if err != nil {
		return nil, err
	}

	return &permission, nil
}

func (app *application) sysGetAppConfigs(appTypeID string, orgID *string, versionNumbers *model.VersionNumbers) ([]model.ApplicationConfig, error) {
	//get the app type
	applicationType, err := app.storage.FindApplicationType(appTypeID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationType, logutils.StringArgs(appTypeID), err)
	}
	if applicationType == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationType, logutils.StringArgs(appTypeID))
	}

	appID := applicationType.Application.ID
	var appOrgID *string
	if orgID != nil {
		appOrg, err := app.storage.FindApplicationOrganization(appID, *orgID)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": appID, "org_id": *orgID}, err)
		}
		if appOrg == nil {
			return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": appID, "org_id": *orgID})
		}
		appOrgID = &appOrg.ID
	}

	appConfigs, err := app.storage.FindAppConfigs(appTypeID, appOrgID, versionNumbers)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationConfig, nil, err)
	}

	return appConfigs, nil
}

func (app *application) sysGetAppConfig(id string) (*model.ApplicationConfig, error) {
	appConfig, err := app.storage.FindAppConfigByID(id)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationConfig, nil, err)
	}

	return appConfig, nil
}

func (app *application) sysCreateAppConfig(appTypeID string, orgID *string, data map[string]interface{}, versionNumbers model.VersionNumbers) (*model.ApplicationConfig, error) {
	//get the app type
	applicationType, err := app.storage.FindApplicationType(appTypeID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationType, logutils.StringArgs(appTypeID), err)
	}
	if applicationType == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationType, logutils.StringArgs(appTypeID))
	}
	if len(applicationType.Versions) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationTypeVersionList, logutils.StringArgs(appTypeID))
	}

	var appOrg *model.ApplicationOrganization
	if orgID != nil {
		appOrg, err = app.storage.FindApplicationOrganization(applicationType.Application.ID, *orgID)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": applicationType.Application.ID, "org_id": *orgID}, err)
		}
	}

	for _, supportedVersion := range applicationType.Versions {
		if versionNumbers == supportedVersion.VersionNumbers {
			now := time.Now()
			appConfigID, _ := uuid.NewUUID()
			applicationConfig := model.ApplicationConfig{ID: appConfigID.String(), Version: supportedVersion, ApplicationType: *applicationType, AppOrg: appOrg, Data: data, DateCreated: now}

			insertedConfig, err := app.storage.InsertAppConfig(applicationConfig)
			if err != nil {
				return nil, errors.WrapErrorAction(logutils.ActionCreate, model.TypeApplicationConfig, nil, err)
			}

			return insertedConfig, nil
		}
	}

	return nil, errors.ErrorData(logutils.StatusInvalid, model.TypeApplicationConfigsVersion, logutils.StringArgs(versionNumbers.String()+" for app_type_id: "+appTypeID))
}

func (app *application) sysUpdateAppConfig(id string, appTypeID string, orgID *string, data map[string]interface{}, versionNumbers model.VersionNumbers) error {
	applicationType, err := app.storage.FindApplicationType(appTypeID)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationType, logutils.StringArgs(appTypeID), err)

	}
	if applicationType == nil {
		return errors.ErrorData(logutils.StatusMissing, model.TypeApplicationType, logutils.StringArgs(appTypeID))
	}
	if len(applicationType.Versions) == 0 {
		return errors.ErrorData(logutils.StatusMissing, model.TypeApplicationTypeVersionList, logutils.StringArgs(appTypeID))
	}

	var appOrg *model.ApplicationOrganization
	if orgID != nil {
		appOrg, err = app.storage.FindApplicationOrganization(applicationType.Application.ID, *orgID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": applicationType.Application.ID, "org_id": *orgID}, err)
		}
	}

	for _, supportedVersion := range applicationType.Versions {
		if versionNumbers == supportedVersion.VersionNumbers {

			err := app.storage.UpdateAppConfig(id, *applicationType, appOrg, supportedVersion, data)
			if err != nil {
				return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeApplicationConfig, nil, err)
			}

			return nil
		}
	}

	return errors.ErrorData(logutils.StatusInvalid, model.TypeApplicationConfigsVersion, logutils.StringArgs(versionNumbers.String()+" for app_type_id: "+appTypeID))
}

func (app *application) sysDeleteAppConfig(id string) error {
	err := app.storage.DeleteAppConfig(id)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeApplicationConfig, nil, err)
	}

	return nil
}
