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
	CreateAnonymousProfile(l *logs.Log, profile *model.AnonymousProfile) (*model.AnonymousProfile, error)
	GetAnonymousProfile(l *logs.Log, id string) (*model.AnonymousProfile, error)
	UpdateAnonymousProfile(l *logs.Log, id string, favorites *[]string, interests *[]string,
		negativeInterestTags *[]string, positiveInterestTags *[]string, privacySettings *string, over13 *bool) error
	DeleteAnonymousProfile(l *logs.Log, id string) error
	UpdateUserAnonymousProfile(l *logs.Log, id string, profile *model.UserAnonymousProfile) error
}

//Administration exposes administration APIs for the driver adapters
type Administration interface {
	AdmGetTest() string
	AdmGetTestModel() string

	AdmCreateGlobalConfig(setting string) (*model.GlobalConfig, error)
	AdmGetGlobalConfig() (*model.GlobalConfig, error)
	AdmUpdateGlobalConfig(setting string) error

	AdmCreateOrganization(name string, requestType string, requiresOwnLogin bool, loginTypes []string, organizationDomains []string) (*model.Organization, error)
	AdmUpdateOrganization(ID string, name string, requestType string, requiresOwnLogin bool, loginTypes []string, organizationDomains []string) error
	AdmGetOrganizations() ([]model.Organization, error)
	AdmGetOrganization(ID string) (*model.Organization, error)

	AdmGetApplication(ID string) (*model.Application, error)
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

	InsertOrganization(organization model.Organization) (*model.Organization, error)
	UpdateOrganization(ID string, name string, requestType string, requiresOwnLogin bool, loginTypes []string, organizationDomains []string) error
	GetOrganizations() ([]model.Organization, error)
	InsertAnonymousProfile(profile *model.AnonymousProfile) (*model.AnonymousProfile, error)
	FindAnonymousProfile(id string) (*model.AnonymousProfile, error)
	UpdateAnonymousProfile(id string, favorites *[]string, interests *[]string,
		negativeInterestTags *[]string, positiveInterestTags *[]string, privacySettings *string, over13 *bool) error
	DeleteAnonymousProfile(id string) error
	FindUserByID(id string) (*model.User, error)
	UpdateUser(user *model.User, newOrgData *map[string]interface{}) (*model.User, error)
	FindOrganization(id string) (*model.Organization, error)

	GetApplication(ID string) (*model.Application, error)
}

//StorageListener listenes for change data storage events
type StorageListener struct {
	app *application
	storage.DefaultListenerImpl
}

//ApplicationListener represents application listener
type ApplicationListener interface {
}
