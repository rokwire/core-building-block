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
	"time"

	"github.com/google/uuid"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
)

func (app *application) sysCreateGlobalConfig(setting string) (*model.GlobalConfig, error) {
	gc, err := app.storage.GetGlobalConfig()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeGlobalConfig, nil, err)
	}
	if gc != nil {
		return nil, errors.New("global config already exists")
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

func (app *application) sysCreateOrganization(name string, requestType string, organizationDomains []string) (*model.Organization, error) {
	now := time.Now()

	orgConfigID, _ := uuid.NewUUID()
	orgConfig := model.OrganizationConfig{ID: orgConfigID.String(), Domains: organizationDomains, DateCreated: now}

	organizationID, _ := uuid.NewUUID()
	organization := model.Organization{ID: organizationID.String(), Name: name, Type: requestType, Config: orgConfig, DateCreated: now}

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
	appAdm, err := app.storage.FindApplication(ID)
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

	applicationID, _ := uuid.NewUUID()
	application := model.Application{ID: applicationID.String(), Name: name, MultiTenant: multiTenant, Admin: admin, SharedIdentities: sharedIdentities,
		Types: appTypes, DateCreated: now}

	insertedApplication, err := app.storage.InsertApplication(nil, application)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplication, nil, err)
	}
	return insertedApplication, nil
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

func (app *application) sysGetAppConfigs(appTypeID string, appID *string, orgID *string, versionNumbers *model.VersionNumbers) ([]model.ApplicationConfig, error) {
	if appTypeID != "" {
		//get the app type
		applicationType, err := app.storage.FindApplicationType(appTypeID)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationType, logutils.StringArgs(appTypeID), err)
		}
		if applicationType == nil {
			return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationType, logutils.StringArgs(appTypeID))
		}
		appID = &applicationType.Application.ID
	}

	if appID == nil {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationID, logutils.StringArgs(appTypeID))
	}

	var appOrgID *string
	if orgID != nil {
		appOrg, err := app.storage.FindApplicationOrganization(*appID, *orgID)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": appID, "org_id": *orgID}, err)
		}
		appOrgID = &appOrg.ID
	}

	_, patchAppConfigs, err := app.storage.FindAppConfigs(*appID, appTypeID, appOrgID, versionNumbers)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationConfig, nil, err)
	}
	// var resultAppConfigs []model.ApplicationConfig

	// if appTypeID != "" {
	// 	// need to apply a patch file on top of the default appConfig
	// 	var basePatchAppConfig *model.ApplicationConfig
	// 	var patchAppConfigMap map[model.VersionNumbers]model.ApplicationConfig

	// 	if len(patchAppConfigs) > 0 {
	// 		for _, patchAppConfig := range patchAppConfigs {
	// 			patchAppConfigMap[patchAppConfig.Version.VersionNumbers] = patchAppConfig
	// 		}

	// 		basePatchAppConfig = &patchAppConfigs[len(patchAppConfigs)-1]
	// 		if !basePatchAppConfig.IsBasePatchFile() {
	// 			// TODO: handle missing base patch file
	// 		}
	// 	}
	// 	println(basePatchAppConfig)

	// 	for _, defaultAppConfig := range defaultAppConfigs {
	// 		var mergedAppConfig model.ApplicationConfig
	// 		versionNumbers := defaultAppConfig.Version.VersionNumbers
	// 		if patch, ok := patchAppConfigMap[versionNumbers]; ok {
	// 			mergedAppConfig = defaultAppConfig.MergeAppConfig(&patch)
	// 		} else {
	// 			mergedAppConfig = defaultAppConfig.MergeAppConfig(basePatchAppConfig)
	// 		}
	// 		resultAppConfigs = append(resultAppConfigs, mergedAppConfig)
	// 	}

	// 	return resultAppConfigs, nil
	// }

	return patchAppConfigs, nil
}

func (app *application) sysGetAppConfig(id string) (*model.ApplicationConfig, error) {
	appConfig, err := app.storage.FindAppConfigByID(id)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationConfig, nil, err)
	}

	return appConfig, nil
}

func (app *application) sysCreateAppConfig(appTypeID string, appID *string, orgID *string, data map[string]interface{}, versionNumbers model.VersionNumbers) (*model.ApplicationConfig, error) {
	var applicationType *model.ApplicationType
	var err error
	if appTypeID != "" {
		applicationType, err = app.storage.FindApplicationType(appTypeID)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationType, logutils.StringArgs(appTypeID), err)
		}
		if applicationType == nil {
			return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationType, logutils.StringArgs(appTypeID))
		}

		appID = &applicationType.Application.ID
	}
	if appID == nil || *appID == "" {
		return nil, errors.ErrorData(logutils.StatusMissing, model.TypeApplicationID, logutils.StringArgs(appTypeID))
	}

	var appOrg *model.ApplicationOrganization
	if orgID != nil {
		appOrg, err = app.storage.FindApplicationOrganization(*appID, *orgID)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": appID, "org_id": *orgID}, err)
		}
		// TODO: appOrg could be nil, but the ParseWebhookFilePath function assumes there's a orgName in the path for now
		// if appOrg == nil {
		// 	return nil, errors.ErrorData(logutils.StatusMissing, model.TypeOrganizationID, nil)
		// }
	}

	var version *model.Version
	if applicationType != nil {
		// Create the app config without checking if it's a supported version
		for _, supportedVersion := range applicationType.Versions {
			if versionNumbers == supportedVersion.VersionNumbers {
				version = &supportedVersion
				break
			}
		}
	}

	now := time.Now()
	appConfigID, _ := uuid.NewUUID()
	if version == nil {
		version = &model.Version{VersionNumbers: versionNumbers, DateCreated: now}
	}

	applicationConfig := model.ApplicationConfig{ID: appConfigID.String(), AppID: *appID, Version: *version, ApplicationType: applicationType, AppOrg: appOrg, Data: data, DateCreated: now}

	insertedConfig, err := app.storage.InsertAppConfig(applicationConfig)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, model.TypeApplicationConfig, nil, err)
	}

	return insertedConfig, nil
}

func (app *application) sysUpdateAppConfig(id string, appTypeID string, appID *string, orgID *string, data map[string]interface{}, versionNumbers model.VersionNumbers) error {
	var applicationType *model.ApplicationType
	var err error

	if appTypeID != "" {
		applicationType, err = app.storage.FindApplicationType(appTypeID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationType, logutils.StringArgs(appTypeID), err)

		}
		if applicationType == nil {
			return errors.ErrorData(logutils.StatusMissing, model.TypeApplicationType, logutils.StringArgs(appTypeID))
		}
		// if len(applicationType.Versions) == 0 {
		// 	return errors.ErrorData(logutils.StatusMissing, model.TypeApplicationTypeVersionList, logutils.StringArgs(appTypeID))
		// }
		appID = &applicationType.Application.ID
	}
	if appID == nil || *appID == "" {
		return errors.ErrorData(logutils.StatusMissing, model.TypeApplicationID, logutils.StringArgs(appTypeID))
	}

	var appOrg *model.ApplicationOrganization
	if orgID != nil {
		appOrg, err = app.storage.FindApplicationOrganization(*appID, *orgID)
		if err != nil {
			return errors.WrapErrorAction(logutils.ActionFind, model.TypeApplicationOrganization, &logutils.FieldArgs{"app_id": *appID, "org_id": *orgID}, err)
		}
	}

	var version *model.Version
	if applicationType != nil {
		for _, supportedVersion := range applicationType.Versions {
			if versionNumbers == supportedVersion.VersionNumbers {
				version = &supportedVersion
				break
			}
		}
	}
	if version == nil {
		version = &model.Version{VersionNumbers: versionNumbers}
	}

	err = app.storage.UpdateAppConfig(id, applicationType, appOrg, *version, data)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeApplicationConfig, nil, err)
	}

	return nil
}

func (app *application) sysDeleteAppConfig(id string) error {
	err := app.storage.DeleteAppConfig(id)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionDelete, model.TypeApplicationConfig, nil, err)
	}

	return nil
}

func (app *application) sysCreateAuthTypes(code string, description string, isExternal bool,
	isAnonymous bool, useCredentials bool, ignoreMFA bool, params map[string]interface{}) (*model.AuthType, error) {

	authTypeID, _ := uuid.NewUUID()
	authType := model.AuthType{ID: authTypeID.String(), Code: code, Description: description,
		IsExternal: isExternal, IsAnonymous: isAnonymous, UseCredentials: useCredentials,
		IgnoreMFA: ignoreMFA, Params: params}

	insertedAuthType, err := app.storage.InsertAuthType(nil, authType)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAuthType, nil, err)
	}
	return insertedAuthType, nil
}

func (app *application) sysGetAuthTypes() ([]model.AuthType, error) {
	getAuthTypes, err := app.storage.FindAuthTypes()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeAuthType, nil, err)
	}

	return getAuthTypes, nil
}

func (app *application) SysUpdateAuthTypes(ID string, code string, description string, isExternal bool, isAnonymous bool, useCredentials bool, ignoreMFA bool, params map[string]interface{}) error {
	err := app.storage.UpdateAuthTypes(ID, code, description, isExternal, isAnonymous, useCredentials, ignoreMFA, params)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUpdate, model.TypeAuthType, nil, err)
	}

	return err

}
