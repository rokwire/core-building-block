package core

import (
	"core-building-block/core/model"
	"core-building-block/driven/storage"

	"github.com/rokmetro/logging-library/logs"
)

//Services exposes APIs for the driver adapters
type Services interface {
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

	AdmCreateApplication(name string, multi_tenant bool, requires_own_users bool) (*model.Application, error)
	AdmGetApplication(ID string) (*model.Application, error)
	AdmGetApplications() ([]model.Application, error)
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

	CreateGlobalConfig(setting string) (*model.GlobalConfig, error)
	GetGlobalConfig() (*model.GlobalConfig, error)
	SaveGlobalConfig(setting *model.GlobalConfig) error

	UpdateApplicationPermission(item model.ApplicationPermission) error
	DeleteApplicationPermission(id string) error

	UpdateApplicationRole(item model.ApplicationRole) error
	DeleteApplicationRole(id string) error

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
