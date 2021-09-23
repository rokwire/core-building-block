// Code generated by mockery v0.0.0-dev. DO NOT EDIT.

package mocks

import (
	model "core-building-block/core/model"

	mock "github.com/stretchr/testify/mock"

	storage "core-building-block/driven/storage"
)

// Storage is an autogenerated mock type for the Storage type
type Storage struct {
	mock.Mock
}

// CreateGlobalConfig provides a mock function with given fields: setting
func (_m *Storage) CreateGlobalConfig(setting string) (*model.GlobalConfig, error) {
	ret := _m.Called(setting)

	var r0 *model.GlobalConfig
	if rf, ok := ret.Get(0).(func(string) *model.GlobalConfig); ok {
		r0 = rf(setting)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.GlobalConfig)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(setting)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// DeleteAccount provides a mock function with given fields: id
func (_m *Storage) DeleteAccount(id string) error {
	ret := _m.Called(id)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteApplicationGroup provides a mock function with given fields: id
func (_m *Storage) DeleteApplicationGroup(id string) error {
	ret := _m.Called(id)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteApplicationPermission provides a mock function with given fields: id
func (_m *Storage) DeleteApplicationPermission(id string) error {
	ret := _m.Called(id)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteApplicationRole provides a mock function with given fields: id
func (_m *Storage) DeleteApplicationRole(id string) error {
	ret := _m.Called(id)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// FindAccountByID provides a mock function with given fields: id
func (_m *Storage) FindAccountByID(id string) (*model.Account, error) {
	ret := _m.Called(id)

	var r0 *model.Account
	if rf, ok := ret.Get(0).(func(string) *model.Account); ok {
		r0 = rf(id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Account)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindApplication provides a mock function with given fields: ID
func (_m *Storage) FindApplication(ID string) (*model.Application, error) {
	ret := _m.Called(ID)

	var r0 *model.Application
	if rf, ok := ret.Get(0).(func(string) *model.Application); ok {
		r0 = rf(ID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Application)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(ID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindApplications provides a mock function with given fields:
func (_m *Storage) FindApplications() ([]model.Application, error) {
	ret := _m.Called()

	var r0 []model.Application
	if rf, ok := ret.Get(0).(func() []model.Application); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.Application)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindOrganization provides a mock function with given fields: id
func (_m *Storage) FindOrganization(id string) (*model.Organization, error) {
	ret := _m.Called(id)

	var r0 *model.Organization
	if rf, ok := ret.Get(0).(func(string) *model.Organization); ok {
		r0 = rf(id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Organization)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// GetGlobalConfig provides a mock function with given fields:
func (_m *Storage) GetGlobalConfig() (*model.GlobalConfig, error) {
	ret := _m.Called()

	var r0 *model.GlobalConfig
	if rf, ok := ret.Get(0).(func() *model.GlobalConfig); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.GlobalConfig)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// InsertApplication provides a mock function with given fields: application
func (_m *Storage) InsertApplication(application model.Application) (*model.Application, error) {
	ret := _m.Called(application)

	var r0 *model.Application
	if rf, ok := ret.Get(0).(func(model.Application) *model.Application); ok {
		r0 = rf(application)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Application)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(model.Application) error); ok {
		r1 = rf(application)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// InsertOrganization provides a mock function with given fields: organization
func (_m *Storage) InsertOrganization(organization model.Organization) (*model.Organization, error) {
	ret := _m.Called(organization)

	var r0 *model.Organization
	if rf, ok := ret.Get(0).(func(model.Organization) *model.Organization); ok {
		r0 = rf(organization)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Organization)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(model.Organization) error); ok {
		r1 = rf(organization)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// LoadApplications provides a mock function with given fields:
func (_m *Storage) LoadApplications() ([]model.Application, error) {
	ret := _m.Called()

	var r0 []model.Application
	if rf, ok := ret.Get(0).(func() []model.Application); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.Application)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// LoadOrganizations provides a mock function with given fields:
func (_m *Storage) LoadOrganizations() ([]model.Organization, error) {
	ret := _m.Called()

	var r0 []model.Organization
	if rf, ok := ret.Get(0).(func() []model.Organization); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.Organization)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func() error); ok {
		r1 = rf()
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// RegisterStorageListener provides a mock function with given fields: storageListener
func (_m *Storage) RegisterStorageListener(storageListener storage.Listener) {
	_m.Called(storageListener)
}

// SaveGlobalConfig provides a mock function with given fields: setting
func (_m *Storage) SaveGlobalConfig(setting *model.GlobalConfig) error {
	ret := _m.Called(setting)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.GlobalConfig) error); ok {
		r0 = rf(setting)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateAccount provides a mock function with given fields: updatedUser, orgID, newOrgData
func (_m *Storage) UpdateAccount(updatedUser *model.Account, orgID string, newOrgData *map[string]interface{}) (*model.Account, error) {
	ret := _m.Called(updatedUser, orgID, newOrgData)

	var r0 *model.Account
	if rf, ok := ret.Get(0).(func(*model.Account, string, *map[string]interface{}) *model.Account); ok {
		r0 = rf(updatedUser, orgID, newOrgData)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Account)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Account, string, *map[string]interface{}) error); ok {
		r1 = rf(updatedUser, orgID, newOrgData)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdateAccountPreferences provides a mock function with given fields: accountID, preferences
func (_m *Storage) UpdateAccountPreferences(accountID string, preferences map[string]interface{}) error {
	ret := _m.Called(accountID, preferences)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, map[string]interface{}) error); ok {
		r0 = rf(accountID, preferences)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateApplicationGroup provides a mock function with given fields: item
func (_m *Storage) UpdateApplicationGroup(item model.ApplicationGroup) error {
	ret := _m.Called(item)

	var r0 error
	if rf, ok := ret.Get(0).(func(model.ApplicationGroup) error); ok {
		r0 = rf(item)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateApplicationPermission provides a mock function with given fields: item
func (_m *Storage) UpdateApplicationPermission(item model.ApplicationPermission) error {
	ret := _m.Called(item)

	var r0 error
	if rf, ok := ret.Get(0).(func(model.ApplicationPermission) error); ok {
		r0 = rf(item)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateApplicationRole provides a mock function with given fields: item
func (_m *Storage) UpdateApplicationRole(item model.ApplicationRole) error {
	ret := _m.Called(item)

	var r0 error
	if rf, ok := ret.Get(0).(func(model.ApplicationRole) error); ok {
		r0 = rf(item)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateOrganization provides a mock function with given fields: ID, name, requestType, organizationDomains
func (_m *Storage) UpdateOrganization(ID string, name string, requestType string, organizationDomains []string) error {
	ret := _m.Called(ID, name, requestType, organizationDomains)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string, string, []string) error); ok {
		r0 = rf(ID, name, requestType, organizationDomains)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateProfile provides a mock function with given fields: profile, ID
func (_m *Storage) UpdateProfile(profile *model.Profile, ID string) error {
	ret := _m.Called(profile, ID)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.Profile, string) error); ok {
		r0 = rf(profile, ID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
