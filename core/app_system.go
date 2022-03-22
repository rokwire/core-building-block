package core

import (
	"core-building-block/core/model"
	"core-building-block/driven/storage"
	"time"

	"github.com/google/uuid"
	"github.com/rokwire/core-auth-library-go/authutils"
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

	insertedOrg, err := app.storage.InsertOrganization(organization)
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

func (app *application) sysCreateApplication(name string, multiTenant bool, sharedIdentities bool, maxLoginSessionDuration *int, identifier string, nameInType string, versions []string) (*model.Application, error) {
	/*now := time.Now()

	applicationID, _ := uuid.NewUUID()
	application := model.Application{ID: applicationID.String(), Name: name, MultiTenant: multiTenant, SharedIdentities: sharedIdentities,
		DateCreated: now}

	insertedApplication, err := app.storage.InsertApplication(application)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeApplication, nil, err)
	}*/
	return /*insertedApplication,*/ nil, nil
}

func (app *application) sysGetApplications() ([]model.Application, error) {
	getApplications, err := app.storage.FindApplications()
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionGet, model.TypeApplication, nil, err)
	}

	return getApplications, nil
}

func (app *application) sysCreatePermission(name string, serviceID string, assigners *[]string) (*model.Permission, error) {
	id, _ := uuid.NewUUID()
	now := time.Now()
	permission := model.Permission{ID: id.String(), Name: name, DateCreated: now, ServiceID: serviceID, Assigners: *assigners}

	err := app.storage.InsertPermission(permission)

	if err != nil {
		return nil, err
	}
	return &permission, nil
}

func (app *application) sysUpdatePermission(name string, serviceID *string, assigners *[]string) (*model.Permission, error) {
	permissionNames := []string{name}
	permissions, err := app.storage.FindPermissionsByName(permissionNames)
	if err != nil {
		return nil, err
	}
	if permissions == nil || len(permissions) < 1 {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypePermission, nil, err)
	}

	permission := permissions[0]
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

func (app *application) sysCreateAppOrgRole(name string, appOrgID string, description string, permissionNames []string) (*model.AppOrgRole, error) {
	permissions, err := app.storage.FindPermissionsByName(permissionNames)
	if err != nil {
		return nil, err
	}

	//TODO - load ApplicationOrganization

	id, _ := uuid.NewUUID()
	now := time.Now()
	role := model.AppOrgRole{ID: id.String(), Name: name, Description: description, AppOrg: model.ApplicationOrganization{ID: appOrgID}, Permissions: permissions, DateCreated: now}
	err = app.storage.InsertAppOrgRole(role)
	if err != nil {
		return nil, err
	}
	return &role, nil
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

func (app *application) sysGrantAccountPermissions(accountID string, permissionNames []string, assignerPermissions []string) error {
	if assignerPermissions == nil {
		return errors.New("no permissions from admin assigner")
	}

	permissions, err := app.storage.FindPermissionsByName(permissionNames)
	if err != nil {
		return err
	}

	if len(permissions) == 0 {
		return errors.Newf("no permissions found for names: %v", permissionNames)
	}

	var authorizedPermissions []model.Permission
	for _, permission := range permissions {
		authorizedAssigners := permission.Assigners
		for _, authorizedAssigner := range authorizedAssigners {
			if authutils.ContainsString(assignerPermissions, authorizedAssigner) {
				authorizedPermissions = append(authorizedPermissions, permission)
			}
		}
	}
	if authorizedPermissions == nil {
		return errors.Newf("Assigner is not authorized to assign permissions for names: %v", permissionNames)
	}

	err = app.storage.InsertAccountPermissions(accountID, authorizedPermissions)
	if err != nil {
		return err
	}
	return nil
}

func (app *application) sysGrantAccountRoles(accountID string, appOrgID string, roleIDs []string) error {
	roles, err := app.storage.FindAppOrgRoles(roleIDs, appOrgID)
	if err != nil {
		return err
	}

	if len(roles) == 0 {
		return errors.Newf("no roles found for IDs: %v", roleIDs)
	}

	err = app.storage.InsertAccountRoles(accountID, appOrgID, model.AccountRolesFromAppOrgRoles(roles, true, true))
	if err != nil {
		return err
	}
	return nil
}

func (app *application) sysCreateAuthTypes(code string, description string, isExternal bool,
	isAnonymous bool, useCredentials bool, ignoreMFA bool, params map[string]interface{}) (*model.AuthType, error) {

	authTypeID, _ := uuid.NewUUID()
	authType := model.AuthType{ID: authTypeID.String(), Code: code, Description: description,
		IsExternal: isExternal, IsAnonymous: isAnonymous, UseCredentials: useCredentials,
		IgnoreMFA: ignoreMFA, Params: params}

	insertedAuthType, err := app.storage.InsertAuthType(authType)
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
