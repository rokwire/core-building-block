package core

import (
	"core-building-block/core/model"
	"core-building-block/driven/storage"

	"github.com/rokwire/logging-library-go/logs"
)

//Services exposes APIs for the driver adapters
type Services interface {
	SerDeleteAccount(id string) error
	SerGetAccount(accountID string) (*model.Account, error)
	SerGetProfile(accountID string) (*model.Profile, error)
	SerGetPreferences(accountID string) (map[string]interface{}, error)
	SerUpdateProfile(accountID string, profile *model.Profile) error
	SerUpdateAccountPreferences(id string, preferences map[string]interface{}) error

	SerGetAuthTest(l *logs.Log) string
	SerGetCommonTest(l *logs.Log) string

	SerGetAppConfig(appTypeIdentifier string, orgID *string, versionNumbers model.VersionNumbers, apiKey *string) (*model.ApplicationConfig, error)
}

//Administration exposes administration APIs for the driver adapters
type Administration interface {
	AdmGetTest() string
	AdmGetTestModel() string

	AdmGetAccounts(appID string, orgID string, accountID *string, authTypeIdentifier *string) ([]model.Account, error)
	AdmGetAccount(accountID string) (*model.Account, error)
}

//Encryption exposes APIs for the Encryption building block
type Encryption interface {
	EncGetTest() string
}

//BBs exposes users related APIs used by the platform building blocks
type BBs interface {
	BBsGetTest() string
}

//System exposes system APIs for the driver adapters
type System interface {
	SysCreateGlobalConfig(setting string) (*model.GlobalConfig, error)
	SysGetGlobalConfig() (*model.GlobalConfig, error)
	SysUpdateGlobalConfig(setting string) error

	SysCreateOrganization(name string, requestType string, organizationDomains []string) (*model.Organization, error)
	SysGetOrganizations() ([]model.Organization, error)
	SysGetOrganization(ID string) (*model.Organization, error)
	SysUpdateOrganization(ID string, name string, requestType string, organizationDomains []string) error

	SysCreateApplication(name string, multiTenant bool, requiresOwnUsers bool, maxLoginSessionDuration *int, identifier string, nameInType string, versions []string) (*model.Application, error)
	SysGetApplication(ID string) (*model.Application, error)
	SysGetApplications() ([]model.Application, error)

	SysCreatePermission(name string, serviceID string, assigners *[]string) (*model.Permission, error)
	SysUpdatePermission(name string, serviceID *string, assigners *[]string) (*model.Permission, error)

	SysCreateAppOrgRole(name string, appID string, description string, permissionNames []string) (*model.AppOrgRole, error)

	SysGetAppConfigs(appTypeID string, orgID *string, versionNumbers *model.VersionNumbers) ([]model.ApplicationConfig, error)
	SysGetAppConfig(id string) (*model.ApplicationConfig, error)
	SysCreateAppConfig(appTypeID string, orgID *string, data map[string]interface{}, versionNumbers model.VersionNumbers) (*model.ApplicationConfig, error)
	SysUpdateAppConfig(id string, appTypeID string, data map[string]interface{}, versionNumbers model.VersionNumbers) error
	SysDeleteAppConfig(id string) error

	SysGrantAccountPermissions(accountID string, permissionNames []string, assignerPermissions []string) error
	SysGrantAccountRoles(accountID string, appID string, roleIDs []string) error
}

//Storage is used by core to storage data - DB storage adapter, file storage adapter etc
type Storage interface {
	RegisterStorageListener(storageListener storage.Listener)

	PerformTransaction(func(context storage.TransactionContext) error) error

	FindAccountByID(context storage.TransactionContext, id string) (*model.Account, error)
	FindAccounts(appID string, orgID string, accountID *string, authTypeIdentifier *string) ([]model.Account, error)
	DeleteAccount(context storage.TransactionContext, id string) error
	UpdateAccountPreferences(accountID string, preferences map[string]interface{}) error
	UpdateProfile(accountID string, profile *model.Profile) error
	InsertAccountPermissions(accountID string, permissions []model.Permission) error
	InsertAccountRoles(accountID string, appOrgID string, roles []model.AccountRole) error

	FindCredential(context storage.TransactionContext, ID string) (*model.Credential, error)
	UpdateCredential(context storage.TransactionContext, creds *model.Credential) error
	DeleteCredential(context storage.TransactionContext, ID string) error

	DeleteLoginSessions(context storage.TransactionContext, identifier string) error

	FindApplicationOrganization(appID string, orgID string) (*model.ApplicationOrganization, error)

	SaveDevice(context storage.TransactionContext, device *model.Device) error
	DeleteDevice(context storage.TransactionContext, id string) error

	CreateGlobalConfig(context storage.TransactionContext, globalConfig *model.GlobalConfig) error
	GetGlobalConfig() (*model.GlobalConfig, error)
	DeleteGlobalConfig(context storage.TransactionContext) error

	FindPermissionsByName(names []string) ([]model.Permission, error)
	InsertPermission(item model.Permission) error
	UpdatePermission(item model.Permission) error
	DeletePermission(id string) error

	FindAppOrgRoles(ids []string, appOrgID string) ([]model.AppOrgRole, error)
	InsertAppOrgRole(item model.AppOrgRole) error
	UpdateAppOrgRole(item model.AppOrgRole) error
	DeleteAppOrgRole(id string) error

	InsertAppOrgGroup(item model.AppOrgGroup) error
	UpdateAppOrgGroup(item model.AppOrgGroup) error
	DeleteAppOrgGroup(id string) error

	InsertOrganization(organization model.Organization) (*model.Organization, error)
	UpdateOrganization(ID string, name string, requestType string, organizationDomains []string) error
	LoadOrganizations() ([]model.Organization, error)
	FindOrganization(id string) (*model.Organization, error)

	LoadApplications() ([]model.Application, error)
	InsertApplication(application model.Application) (*model.Application, error)
	FindApplication(ID string) (*model.Application, error)
	FindApplications() ([]model.Application, error)

	FindApplicationType(id string) (*model.ApplicationType, error)

	FindAppConfigs(appTypeIdentifier string, orgID *string, versionNumbers *model.VersionNumbers) ([]model.ApplicationConfig, error)
	FindAppConfigByVersion(appTypeIdentifier string, orgID *string, versionNumbers model.VersionNumbers) (*model.ApplicationConfig, error)
	FindAppConfigByID(ID string) (*model.ApplicationConfig, error)
	InsertAppConfig(appConfig model.ApplicationConfig) (*model.ApplicationConfig, error)
	UpdateAppConfig(ID string, appType model.ApplicationType, version model.Version, data map[string]interface{}) error
	DeleteAppConfig(ID string) error
}

//StorageListener listenes for change data storage events
type StorageListener struct {
	app *application
	storage.DefaultListenerImpl
}

//ApplicationListener represents application listener
type ApplicationListener interface {
}
