// Code generated by mockery 2.9.0. DO NOT EDIT.

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

// CreatePII provides a mock function with given fields: profile, ID
func (_m *Storage) CreatePII(profile *model.UserProfile, ID string) error {
	ret := _m.Called(profile, ID)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.UserProfile, string) error); ok {
		r0 = rf(profile, ID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeletePII provides a mock function with given fields: ID
func (_m *Storage) DeletePII(ID string) error {
	ret := _m.Called(ID)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(ID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// GetApplication provides a mock function with given fields: ID
func (_m *Storage) GetApplication(ID string) (*model.Application, error) {
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

// GetOrganizations provides a mock function with given fields:
func (_m *Storage) GetOrganizations() ([]model.Organization, error) {
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

// GetPII provides a mock function with given fields: ID
func (_m *Storage) GetPII(ID string) (*model.UserProfile, error) {
	ret := _m.Called(ID)

	var r0 *model.UserProfile
	if rf, ok := ret.Get(0).(func(string) *model.UserProfile); ok {
		r0 = rf(ID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.UserProfile)
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

// UpdateOrganization provides a mock function with given fields: ID, name, requestType, requiresOwnLogin, loginTypes, organizationDomains
func (_m *Storage) UpdateOrganization(ID string, name string, requestType string, requiresOwnLogin bool, loginTypes []string, organizationDomains []string) error {
	ret := _m.Called(ID, name, requestType, requiresOwnLogin, loginTypes, organizationDomains)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string, string, bool, []string, []string) error); ok {
		r0 = rf(ID, name, requestType, requiresOwnLogin, loginTypes, organizationDomains)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdatePII provides a mock function with given fields: profile, ID
func (_m *Storage) UpdatePII(profile *model.UserProfile, ID string) error {
	ret := _m.Called(profile, ID)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.UserProfile, string) error); ok {
		r0 = rf(profile, ID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
