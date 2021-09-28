package core

import (
	"core-building-block/core/model"
	"core-building-block/driven/storage"

	"github.com/rokmetro/logging-library/logs"
)

//Services exposes APIs for the driver adapters
type Services interface {
	SerDeleteAccount(id string) error
	SerGetProfile(accountID string) (*model.Profile, error)
	SerUpdateProfile(profile *model.Profile, ID string) error
	SerUpdateAccountPreferences(id string, preferences map[string]interface{}) error

	SerGetAuthTest(l *logs.Log) string
	SerGetCommonTest(l *logs.Log) string
}

//Administration exposes administration APIs for the driver adapters
type Administration interface {
	AdmGetTest() string
	AdmGetTestModel() string

	AdmCreateGlobalConfig(setting string) (*model.GlobalConfig, error)
	AdmGetGlobalConfig() (*model.GlobalConfig, error)
	AdmUpdateGlobalConfig(setting string) error

	AdmCreateOrganization(name string, requestType string, organizationDomains []string) (*model.Organization, error)
	AdmGetOrganizations() ([]model.Organization, error)
	AdmGetOrganization(ID string) (*model.Organization, error)
	AdmUpdateOrganization(ID string, name string, requestType string, organizationDomains []string) error

	AdmCreateApplication(name string, versions []string) (*model.Application, error)
	AdmGetApplication(ID string) (*model.Application, error)
	AdmGetApplications() ([]model.Application, error)

	AdmCreateApplicationPermission(name string, appID string) (*model.ApplicationPermission, error)

	AdmCreateApplicationRole(name string, appID string, description string, permissionNames []string) (*model.ApplicationRole, error)

	AdmGrantAccountPermissions(accountID string, appID string, permissionNames []string) error
	AdmGrantAccountRoles(accountID string, appID string, roleIDs []string) error
}

//Encryption exposes APIs for the Encryption building block
type Encryption interface {
	EncGetTest() string
}

//BBs exposes users related APIs used by the platform building blocks
type BBs interface {
	BBsGetTest() string
}

//Storage is used by core to storage data - DB storage adapter, file storage adapter etc
type Storage interface {
	RegisterStorageListener(storageListener storage.Listener)

	FindAccountByID(id string) (*model.Account, error)
	UpdateProfile(profile *model.Profile, ID string) error
	UpdateAccountPreferences(accountID string, preferences map[string]interface{}) error
	InsertAccountPermissions(accountID string, appID string, permissions []model.ApplicationPermission) error
	InsertAccountRoles(accountID string, appID string, roles []model.ApplicationRole) error
	DeleteAccount(id string) error

	CreateGlobalConfig(setting string) (*model.GlobalConfig, error)
	GetGlobalConfig() (*model.GlobalConfig, error)
	SaveGlobalConfig(setting *model.GlobalConfig) error

	FindApplicationPermissionsByName(names []string, appID string) ([]model.ApplicationPermission, error)
	InsertApplicationPermission(item model.ApplicationPermission) error
	UpdateApplicationPermission(item model.ApplicationPermission) error
	DeleteApplicationPermission(id string) error

	FindApplicationRoles(ids []string, appID string) ([]model.ApplicationRole, error)
	InsertApplicationRole(item model.ApplicationRole) error
	UpdateApplicationRole(item model.ApplicationRole) error
	DeleteApplicationRole(id string) error

	InsertApplicationGroup(item model.ApplicationGroup) error
	UpdateApplicationGroup(item model.ApplicationGroup) error
	DeleteApplicationGroup(id string) error

	InsertOrganization(organization model.Organization) (*model.Organization, error)
	UpdateOrganization(ID string, name string, requestType string, organizationDomains []string) error
	LoadOrganizations() ([]model.Organization, error)
	FindOrganization(id string) (*model.Organization, error)

	LoadApplications() ([]model.Application, error)
	InsertApplication(application model.Application) (*model.Application, error)
	FindApplication(ID string) (*model.Application, error)
	FindApplications() ([]model.Application, error)
}

//StorageListener listenes for change data storage events
type StorageListener struct {
	app *application
	storage.DefaultListenerImpl
}

//ApplicationListener represents application listener
type ApplicationListener interface {
}
