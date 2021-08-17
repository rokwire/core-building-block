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

// DeleteGlobalGroup provides a mock function with given fields: id
func (_m *Storage) DeleteGlobalGroup(id string) error {
	ret := _m.Called(id)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteGlobalPermission provides a mock function with given fields: id
func (_m *Storage) DeleteGlobalPermission(id string) error {
	ret := _m.Called(id)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteGlobalRole provides a mock function with given fields: id
func (_m *Storage) DeleteGlobalRole(id string) error {
	ret := _m.Called(id)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteOrganizationGroup provides a mock function with given fields: id
func (_m *Storage) DeleteOrganizationGroup(id string) error {
	ret := _m.Called(id)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteOrganizationPermission provides a mock function with given fields: id
func (_m *Storage) DeleteOrganizationPermission(id string) error {
	ret := _m.Called(id)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteOrganizationRole provides a mock function with given fields: id
func (_m *Storage) DeleteOrganizationRole(id string) error {
	ret := _m.Called(id)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
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

// FindGlobalGroup provides a mock function with given fields: ID
func (_m *Storage) FindGlobalGroup(ID string) (*model.GlobalGroup, error) {
	ret := _m.Called(ID)

	var r0 *model.GlobalGroup
	if rf, ok := ret.Get(0).(func(string) *model.GlobalGroup); ok {
		r0 = rf(ID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.GlobalGroup)
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

// FindGlobalPermissions provides a mock function with given fields: ids
func (_m *Storage) FindGlobalPermissions(ids []string) ([]model.GlobalPermission, error) {
	ret := _m.Called(ids)

	var r0 []model.GlobalPermission
	if rf, ok := ret.Get(0).(func([]string) []model.GlobalPermission); ok {
		r0 = rf(ids)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.GlobalPermission)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func([]string) error); ok {
		r1 = rf(ids)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindGlobalRoles provides a mock function with given fields: ids
func (_m *Storage) FindGlobalRoles(ids []string) ([]model.GlobalRole, error) {
	ret := _m.Called(ids)

	var r0 []model.GlobalRole
	if rf, ok := ret.Get(0).(func([]string) []model.GlobalRole); ok {
		r0 = rf(ids)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.GlobalRole)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func([]string) error); ok {
		r1 = rf(ids)
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

// InsertGlobalGroup provides a mock function with given fields: globalGroup
func (_m *Storage) InsertGlobalGroup(globalGroup model.GlobalGroup) (*model.GlobalGroup, error) {
	ret := _m.Called(globalGroup)

	var r0 *model.GlobalGroup
	if rf, ok := ret.Get(0).(func(model.GlobalGroup) *model.GlobalGroup); ok {
		r0 = rf(globalGroup)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.GlobalGroup)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(model.GlobalGroup) error); ok {
		r1 = rf(globalGroup)
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

// UpdateGlobalGroup provides a mock function with given fields: item
func (_m *Storage) UpdateGlobalGroup(item model.GlobalGroup) error {
	ret := _m.Called(item)

	var r0 error
	if rf, ok := ret.Get(0).(func(model.GlobalGroup) error); ok {
		r0 = rf(item)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateGlobalPermission provides a mock function with given fields: item
func (_m *Storage) UpdateGlobalPermission(item model.GlobalPermission) error {
	ret := _m.Called(item)

	var r0 error
	if rf, ok := ret.Get(0).(func(model.GlobalPermission) error); ok {
		r0 = rf(item)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateGlobalRole provides a mock function with given fields: item
func (_m *Storage) UpdateGlobalRole(item model.GlobalRole) error {
	ret := _m.Called(item)

	var r0 error
	if rf, ok := ret.Get(0).(func(model.GlobalRole) error); ok {
		r0 = rf(item)
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

// UpdateOrganizationGroup provides a mock function with given fields: item
func (_m *Storage) UpdateOrganizationGroup(item model.OrganizationGroup) error {
	ret := _m.Called(item)

	var r0 error
	if rf, ok := ret.Get(0).(func(model.OrganizationGroup) error); ok {
		r0 = rf(item)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateOrganizationPermission provides a mock function with given fields: item
func (_m *Storage) UpdateOrganizationPermission(item model.OrganizationPermission) error {
	ret := _m.Called(item)

	var r0 error
	if rf, ok := ret.Get(0).(func(model.OrganizationPermission) error); ok {
		r0 = rf(item)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateOrganizationRole provides a mock function with given fields: item
func (_m *Storage) UpdateOrganizationRole(item model.OrganizationRole) error {
	ret := _m.Called(item)

	var r0 error
	if rf, ok := ret.Get(0).(func(model.OrganizationRole) error); ok {
		r0 = rf(item)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
