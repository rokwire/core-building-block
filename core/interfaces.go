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

	"github.com/rokwire/logging-library-go/v2/logs"
)

// Services exposes APIs for the driver adapters
type Services interface {
	SerDeleteAccount(id string) error
	SerGetAccount(accountID string) (*model.Account, error)
	SerGetProfile(accountID string) (*model.Profile, error)
	SerGetPreferences(accountID string) (map[string]interface{}, error)
	SerGetAccountSystemConfigs(accountID string) (map[string]interface{}, error)
	SerUpdateAccountPreferences(id string, appID string, orgID string, anonymous bool, preferences map[string]interface{}, l *logs.Log) (bool, error)
	SerUpdateProfile(accountID string, profile model.Profile) error
	SerUpdateAccountUsername(accountID string, appID string, orgID string, username string) error

	SerGetAccounts(limit int, offset int, appID string, orgID string, accountID *string, firstName *string, lastName *string, authType *string,
		authTypeIdentifier *string, anonymous *bool, hasPermissions *bool, permissions []string, roleIDs []string, groupIDs []string) ([]model.Account, error)

	SerGetAuthTest(l *logs.Log) string
	SerGetCommonTest(l *logs.Log) string

	SerGetAppConfig(appTypeIdentifier string, orgID *string, versionNumbers model.VersionNumbers, apiKey *string) (*model.ApplicationConfig, error)
}

// Administration exposes administration APIs for the driver adapters
type Administration interface {
	AdmGetTest() string
	AdmGetTestModel() string

	AdmGetApplications(orgID string) ([]model.Application, error)

	AdmCreateAppOrgGroup(name string, description string, system bool, permissionNames []string, rolesIDs []string, accountIDs []string, appID string, orgID string, assignerPermissions []string, systemClaim bool, l *logs.Log) (*model.AppOrgGroup, error)
	AdmUpdateAppOrgGroup(ID string, name string, description string, system bool, permissionNames []string, rolesIDs []string, accountIDs []string, appID string, orgID string, assignerPermissions []string, systemClaim bool, l *logs.Log) (*model.AppOrgGroup, error)
	AdmGetAppOrgGroups(appID string, orgID string) ([]model.AppOrgGroup, error)
	AdmAddAccountsToGroup(appID string, orgID string, groupID string, accountIDs []string, assignerPermissions []string, l *logs.Log) error
	AdmRemoveAccountsFromGroup(appID string, orgID string, groupID string, accountIDs []string, assignerPermissions []string, l *logs.Log) error
	AdmDeleteAppOrgGroup(ID string, appID string, orgID string, assignerPermissions []string, system bool, l *logs.Log) error

	AdmCreateAppOrgRole(name string, description string, system bool, permissionNames []string, appID string, orgID string, assignerPermissions []string, systemClaim bool, l *logs.Log) (*model.AppOrgRole, error)
	AdmGetAppOrgRoles(appID string, orgID string) ([]model.AppOrgRole, error)
	AdmUpdateAppOrgRole(ID string, name string, description string, system bool, permissionNames []string, appID string, orgID string, assignerPermissions []string, systemClaim bool, l *logs.Log) (*model.AppOrgRole, error)
	AdmGrantPermissionsToRole(appID string, orgID string, roleID string, permissionNames []string, assignerPermissions []string, system bool, l *logs.Log) error
	AdmDeleteAppOrgRole(ID string, appID string, orgID string, assignerPermissions []string, system bool, l *logs.Log) error

	AdmGetApplicationPermissions(appID string, orgID string, l *logs.Log) ([]model.Permission, error)

	AdmGetAccounts(limit int, offset int, appID string, orgID string, accountID *string, firstName *string, lastName *string, authType *string,
		authTypeIdentifier *string, anonymous *bool, hasPermissions *bool, permissions []string, roleIDs []string, groupIDs []string) ([]model.Account, error)
	AdmGetAccount(accountID string) (*model.Account, error)

	AdmUpdateAccountUsername(accountID string, appID string, orgID string, username string) error

	AdmGetAccountSystemConfigs(appID string, orgID string, accountID string, l *logs.Log) (map[string]interface{}, error)
	AdmUpdateAccountSystemConfigs(appID string, orgID string, accountID string, configs map[string]interface{}, createAnonymous bool, l *logs.Log) (bool, error)

	AdmGrantAccountPermissions(appID string, orgID string, accountID string, permissionNames []string, assignerPermissions []string, l *logs.Log) error
	AdmRevokeAccountPermissions(appID string, orgID string, accountID string, permissions []string, assignerPermissions []string, l *logs.Log) error

	AdmGrantAccountRoles(appID string, orgID string, accountID string, roleIDs []string, assignerPermissions []string, l *logs.Log) error
	AdmRevokeAccountRoles(appID string, orgID string, accountID string, roleIDs []string, assignerPermissions []string, l *logs.Log) error

	AdmGetApplicationLoginSessions(appID string, orgID string, identifier *string, accountAuthTypeIdentifier *string,
		appTypeID *string, appTypeIdentifier *string, anonymous *bool, deviceID *string, ipAddress *string) ([]model.LoginSession, error)
	AdmDeleteApplicationLoginSession(appID string, orgID string, currentAccountID string, identifier string, sessionID string, l *logs.Log) error

	AdmGetApplicationAccountDevices(appID string, orgID string, accountID string, l *logs.Log) ([]model.Device, error)

	AdmGetAppConfig(appTypeIdentifier string, orgID *string, versionNumbers model.VersionNumbers, apiKey *string) (*model.ApplicationConfig, error)
}

// Encryption exposes APIs for the Encryption building block
type Encryption interface {
	EncGetTest() string
}

// BBs exposes users related APIs used by the platform building blocks
type BBs interface {
	BBsGetTest() string

	BBsGetAccounts(searchParams map[string]interface{}, appID string, orgID string, limit int, offset int, allAccess bool, approvedKeys []string) ([]map[string]interface{}, error)
	BBsGetAccountsCount(searchParams map[string]interface{}, appID string, orgID string) (int64, error)
}

// TPS exposes user related APIs used by third-party services
type TPS interface {
	TPSGetAccounts(searchParams map[string]interface{}, appID string, orgID string, limit int, offset int, allAccess bool, approvedKeys []string) ([]map[string]interface{}, error)
	TPSGetAccountsCount(searchParams map[string]interface{}, appID string, orgID string) (int64, error)
}

// System exposes system APIs for the driver adapters
type System interface {
	SysCreateGlobalConfig(setting string) (*model.GlobalConfig, error)
	SysGetGlobalConfig() (*model.GlobalConfig, error)
	SysUpdateGlobalConfig(setting string) error

	SysGetApplicationOrganization(ID string) (*model.ApplicationOrganization, error)
	SysGetApplicationOrganizations(appID *string, orgID *string) ([]model.ApplicationOrganization, error)
	SysCreateApplicationOrganization(appOrg model.ApplicationOrganization) error
	SysUpdateApplicationOrganization(updateAppOrg model.ApplicationOrganization) error

	SysCreateOrganization(name string, requestType string, organizationDomains []string) (*model.Organization, error)
	SysGetOrganizations() ([]model.Organization, error)
	SysGetOrganization(ID string) (*model.Organization, error)
	SysUpdateOrganization(ID string, name string, requestType string, organizationDomains []string) error

	SysCreateApplication(name string, multiTenant bool, admin bool, sharedIdentities bool, appTypes []model.ApplicationType) (*model.Application, error)
	SysUpdateApplication(ID string, name string, multiTenant bool, admin bool, sharedIdentities bool, appTypes []model.ApplicationType) error
	SysGetApplication(ID string) (*model.Application, error)
	SysGetApplications() ([]model.Application, error)

	SysCreatePermission(name string, description *string, serviceID *string, assigners *[]string) (*model.Permission, error)
	SysUpdatePermission(name string, description *string, serviceID *string, assigners *[]string) (*model.Permission, error)

	SysGetAppConfigs(appTypeID string, orgID *string, versionNumbers *model.VersionNumbers) ([]model.ApplicationConfig, error)
	SysGetAppConfig(id string) (*model.ApplicationConfig, error)
	SysCreateAppConfig(appTypeID string, orgID *string, data map[string]interface{}, versionNumbers model.VersionNumbers) (*model.ApplicationConfig, error)
	SysUpdateAppConfig(id string, appTypeID string, orgID *string, data map[string]interface{}, versionNumbers model.VersionNumbers) error
	SysDeleteAppConfig(id string) error
}

// Storage is used by core to storage data - DB storage adapter, file storage adapter etc
type Storage interface {
	RegisterStorageListener(storageListener storage.Listener)

	PerformTransaction(func(context storage.TransactionContext) error) error

	FindAccountByID(context storage.TransactionContext, id string) (*model.Account, error)
	FindAccounts(context storage.TransactionContext, limit *int, offset *int, appID string, orgID string, accountID *string, firstName *string, lastName *string, authType *string,
		authTypeIdentifier *string, anonymous *bool, hasPermissions *bool, permissions []string, roleIDs []string, groupIDs []string) ([]model.Account, error)
	FindAccountsByParams(searchParams map[string]interface{}, appID string, orgID string, limit int, offset int, allAccess bool, approvedKeys []string) ([]map[string]interface{}, error)
	CountAccountsByParams(searchParams map[string]interface{}, appID string, orgID string) (int64, error)
	FindAccountsByAccountID(context storage.TransactionContext, appID string, orgID string, accountIDs []string) ([]model.Account, error)
	FindAccountsByUsername(context storage.TransactionContext, appOrg *model.ApplicationOrganization, username string) ([]model.Account, error)

	UpdateAccountPreferences(context storage.TransactionContext, accountID string, preferences map[string]interface{}) error
	UpdateAccountSystemConfigs(context storage.TransactionContext, accountID string, configs map[string]interface{}) error
	InsertAccountPermissions(context storage.TransactionContext, accountID string, permissions []model.Permission) error
	DeleteAccountPermissions(context storage.TransactionContext, accountID string, permissionNames []string) error
	UpdateAccountUsername(context storage.TransactionContext, accountID, username string) error
	InsertAccountRoles(context storage.TransactionContext, accountID string, appOrgID string, roles []model.AccountRole) error
	DeleteAccountRoles(context storage.TransactionContext, accountID string, roleIDs []string) error
	InsertAccountsGroup(context storage.TransactionContext, group model.AccountGroup, accountIDs []string) error
	RemoveAccountsGroup(context storage.TransactionContext, groupID string, accountIDs []string) error
	CountAccountsByRoleID(roleID string) (*int64, error)
	CountAccountsByGroupID(groupID string) (*int64, error)

	UpdateProfile(context storage.TransactionContext, profile model.Profile) error

	FindLoginSessionsByParams(appID string, orgID string, sessionID *string, identifier *string, accountAuthTypeIdentifier *string,
		appTypeID *string, appTypeIdentifier *string, anonymous *bool, deviceID *string, ipAddress *string) ([]model.LoginSession, error)
	DeleteLoginSessionByID(context storage.TransactionContext, id string) error
	DeleteLoginSessionsByIdentifier(context storage.TransactionContext, identifier string) error

	SaveDevice(context storage.TransactionContext, device *model.Device) error
	DeleteDevice(context storage.TransactionContext, id string) error

	CreateGlobalConfig(context storage.TransactionContext, globalConfig *model.GlobalConfig) error
	GetGlobalConfig() (*model.GlobalConfig, error)
	DeleteGlobalConfig(context storage.TransactionContext) error

	FindPermissionsByName(context storage.TransactionContext, names []string) ([]model.Permission, error)
	FindPermissionsByServiceIDs(serviceIDs []string) ([]model.Permission, error)
	InsertPermission(context storage.TransactionContext, item model.Permission) error
	InsertPermissions(context storage.TransactionContext, items []model.Permission) error
	UpdatePermission(item model.Permission) error
	DeletePermission(id string) error

	FindAppOrgRoles(appOrgID string) ([]model.AppOrgRole, error)
	FindAppOrgRolesByIDs(context storage.TransactionContext, ids []string, appOrgID string) ([]model.AppOrgRole, error)
	FindAppOrgRole(context storage.TransactionContext, id string, appOrgID string) (*model.AppOrgRole, error)
	InsertAppOrgRole(context storage.TransactionContext, item model.AppOrgRole) error
	UpdateAppOrgRole(context storage.TransactionContext, item model.AppOrgRole) error
	DeleteAppOrgRole(id string) error
	InsertAppOrgRolePermissions(context storage.TransactionContext, roleID string, permissionNames []model.Permission) error

	FindAppOrgGroups(appOrgID string) ([]model.AppOrgGroup, error)
	FindAppOrgGroupsByIDs(context storage.TransactionContext, ids []string, appOrgID string) ([]model.AppOrgGroup, error)
	FindAppOrgGroup(context storage.TransactionContext, id string, appOrgID string) (*model.AppOrgGroup, error)
	InsertAppOrgGroup(context storage.TransactionContext, item model.AppOrgGroup) error
	UpdateAppOrgGroup(context storage.TransactionContext, item model.AppOrgGroup) error
	DeleteAppOrgGroup(id string) error
	CountGroupsByRoleID(roleID string) (*int64, error)

	InsertOrganization(context storage.TransactionContext, organization model.Organization) (*model.Organization, error)
	UpdateOrganization(ID string, name string, requestType string, organizationDomains []string) error
	FindOrganization(id string) (*model.Organization, error)
	FindSystemOrganization() (*model.Organization, error)
	FindOrganizations() ([]model.Organization, error)

	InsertApplication(context storage.TransactionContext, application model.Application) (*model.Application, error)
	SaveApplication(context storage.TransactionContext, application model.Application) error
	FindApplication(context storage.TransactionContext, ID string) (*model.Application, error)
	FindApplications() ([]model.Application, error)

	FindApplicationType(id string) (*model.ApplicationType, error)

	FindAppConfigs(appTypeIdentifier string, appOrgID *string, versionNumbers *model.VersionNumbers) ([]model.ApplicationConfig, error)
	FindAppConfigByVersion(appTypeIdentifier string, appOrgID *string, versionNumbers model.VersionNumbers) (*model.ApplicationConfig, error)
	FindAppConfigByID(ID string) (*model.ApplicationConfig, error)
	InsertAppConfig(item model.ApplicationConfig) (*model.ApplicationConfig, error)
	UpdateAppConfig(ID string, appType model.ApplicationType, appOrg *model.ApplicationOrganization, version model.Version, data map[string]interface{}) error
	DeleteAppConfig(ID string) error

	FindApplicationsOrganizationsByOrgID(orgID string) ([]model.ApplicationOrganization, error)
	FindApplicationOrganizations(appID *string, orgID *string) ([]model.ApplicationOrganization, error)
	FindApplicationOrganization(appID string, orgID string) (*model.ApplicationOrganization, error)
	FindApplicationOrganizationByID(ID string) (*model.ApplicationOrganization, error)
	InsertApplicationOrganization(context storage.TransactionContext, applicationOrganization model.ApplicationOrganization) error
	UpdateApplicationOrganization(context storage.TransactionContext, applicationOrganization model.ApplicationOrganization) error

	InsertAPIKey(context storage.TransactionContext, apiKey model.APIKey) (*model.APIKey, error)
}

// StorageListener listenes for change data storage events
type StorageListener struct {
	app *application
	storage.DefaultListenerImpl
}

// ApplicationListener represents application listener
type ApplicationListener interface {
}
