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

// CreateGlobalConfig provides a mock function with given fields: context, globalConfig
func (_m *Storage) CreateGlobalConfig(context storage.TransactionContext, globalConfig *model.GlobalConfig) error {
	ret := _m.Called(context, globalConfig)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, *model.GlobalConfig) error); ok {
		r0 = rf(context, globalConfig)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteAccount provides a mock function with given fields: context, id
func (_m *Storage) DeleteAccount(context storage.TransactionContext, id string) error {
	ret := _m.Called(context, id)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string) error); ok {
		r0 = rf(context, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteAppOrgGroup provides a mock function with given fields: id
func (_m *Storage) DeleteAppOrgGroup(id string) error {
	ret := _m.Called(id)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteAppOrgRole provides a mock function with given fields: id
func (_m *Storage) DeleteAppOrgRole(id string) error {
	ret := _m.Called(id)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteCredential provides a mock function with given fields: context, ID
func (_m *Storage) DeleteCredential(context storage.TransactionContext, ID string) error {
	ret := _m.Called(context, ID)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string) error); ok {
		r0 = rf(context, ID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteDevice provides a mock function with given fields: context, id
func (_m *Storage) DeleteDevice(context storage.TransactionContext, id string) error {
	ret := _m.Called(context, id)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string) error); ok {
		r0 = rf(context, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteGlobalConfig provides a mock function with given fields: context
func (_m *Storage) DeleteGlobalConfig(context storage.TransactionContext) error {
	ret := _m.Called(context)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext) error); ok {
		r0 = rf(context)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteLoginSessions provides a mock function with given fields: context, identifier
func (_m *Storage) DeleteLoginSessions(context storage.TransactionContext, identifier string) error {
	ret := _m.Called(context, identifier)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string) error); ok {
		r0 = rf(context, identifier)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteLoginSessionsByAccountAndSessionID provides a mock function with given fields: context, identifier, sessionID
func (_m *Storage) DeleteLoginSessionsByAccountAndSessionID(context storage.TransactionContext, identifier string, sessionID string) error {
	ret := _m.Called(context, identifier, sessionID)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string, string) error); ok {
		r0 = rf(context, identifier, sessionID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeletePermission provides a mock function with given fields: id
func (_m *Storage) DeletePermission(id string) error {
	ret := _m.Called(id)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// FindAccountByID provides a mock function with given fields: context, id
func (_m *Storage) FindAccountByID(context storage.TransactionContext, id string) (*model.Account, error) {
	ret := _m.Called(context, id)

	var r0 *model.Account
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string) *model.Account); ok {
		r0 = rf(context, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Account)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(storage.TransactionContext, string) error); ok {
		r1 = rf(context, id)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindAccounts provides a mock function with given fields: appID, orgID, accountID, authTypeIdentifier
func (_m *Storage) FindAccounts(appID string, orgID string, accountID *string, authTypeIdentifier *string) ([]model.Account, error) {
	ret := _m.Called(appID, orgID, accountID, authTypeIdentifier)

	var r0 []model.Account
	if rf, ok := ret.Get(0).(func(string, string, *string, *string) []model.Account); ok {
		r0 = rf(appID, orgID, accountID, authTypeIdentifier)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.Account)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string, *string, *string) error); ok {
		r1 = rf(appID, orgID, accountID, authTypeIdentifier)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindAppOrgGroups provides a mock function with given fields: ids, appOrgID
func (_m *Storage) FindAppOrgGroups(ids []string, appOrgID string) ([]model.AppOrgGroup, error) {
	ret := _m.Called(ids, appOrgID)

	var r0 []model.AppOrgGroup
	if rf, ok := ret.Get(0).(func([]string, string) []model.AppOrgGroup); ok {
		r0 = rf(ids, appOrgID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.AppOrgGroup)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func([]string, string) error); ok {
		r1 = rf(ids, appOrgID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindAppOrgRoles provides a mock function with given fields: ids, appOrgID
func (_m *Storage) FindAppOrgRoles(ids []string, appOrgID string) ([]model.AppOrgRole, error) {
	ret := _m.Called(ids, appOrgID)

	var r0 []model.AppOrgRole
	if rf, ok := ret.Get(0).(func([]string, string) []model.AppOrgRole); ok {
		r0 = rf(ids, appOrgID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.AppOrgRole)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func([]string, string) error); ok {
		r1 = rf(ids, appOrgID)
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

// FindApplicationOrganizations provides a mock function with given fields: appID, orgID
func (_m *Storage) FindApplicationOrganizations(appID string, orgID string) (*model.ApplicationOrganization, error) {
	ret := _m.Called(appID, orgID)

	var r0 *model.ApplicationOrganization
	if rf, ok := ret.Get(0).(func(string, string) *model.ApplicationOrganization); ok {
		r0 = rf(appID, orgID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.ApplicationOrganization)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string) error); ok {
		r1 = rf(appID, orgID)
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

// FindCredential provides a mock function with given fields: context, ID
func (_m *Storage) FindCredential(context storage.TransactionContext, ID string) (*model.Credential, error) {
	ret := _m.Called(context, ID)

	var r0 *model.Credential
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string) *model.Credential); ok {
		r0 = rf(context, ID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Credential)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(storage.TransactionContext, string) error); ok {
		r1 = rf(context, ID)
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

// FindPermissionsByName provides a mock function with given fields: names
func (_m *Storage) FindPermissionsByName(names []string) ([]model.Permission, error) {
	ret := _m.Called(names)

	var r0 []model.Permission
	if rf, ok := ret.Get(0).(func([]string) []model.Permission); ok {
		r0 = rf(names)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.Permission)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func([]string) error); ok {
		r1 = rf(names)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindPermissionsByServiceIDs provides a mock function with given fields: serviceIDs
func (_m *Storage) FindPermissionsByServiceIDs(serviceIDs []string) ([]model.Permission, error) {
	ret := _m.Called(serviceIDs)

	var r0 []model.Permission
	if rf, ok := ret.Get(0).(func([]string) []model.Permission); ok {
		r0 = rf(serviceIDs)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.Permission)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func([]string) error); ok {
		r1 = rf(serviceIDs)
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

// InsertAccountPermissions provides a mock function with given fields: accountID, permissions
func (_m *Storage) InsertAccountPermissions(accountID string, permissions []model.Permission) error {
	ret := _m.Called(accountID, permissions)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, []model.Permission) error); ok {
		r0 = rf(accountID, permissions)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// InsertAccountRoles provides a mock function with given fields: accountID, appOrgID, roles
func (_m *Storage) InsertAccountRoles(accountID string, appOrgID string, roles []model.AccountRole) error {
	ret := _m.Called(accountID, appOrgID, roles)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string, []model.AccountRole) error); ok {
		r0 = rf(accountID, appOrgID, roles)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// InsertAppOrgGroup provides a mock function with given fields: item
func (_m *Storage) InsertAppOrgGroup(item model.AppOrgGroup) error {
	ret := _m.Called(item)

	var r0 error
	if rf, ok := ret.Get(0).(func(model.AppOrgGroup) error); ok {
		r0 = rf(item)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// InsertAppOrgRole provides a mock function with given fields: item
func (_m *Storage) InsertAppOrgRole(item model.AppOrgRole) error {
	ret := _m.Called(item)

	var r0 error
	if rf, ok := ret.Get(0).(func(model.AppOrgRole) error); ok {
		r0 = rf(item)
	} else {
		r0 = ret.Error(0)
	}

	return r0
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

// InsertPermission provides a mock function with given fields: item
func (_m *Storage) InsertPermission(item model.Permission) error {
	ret := _m.Called(item)

	var r0 error
	if rf, ok := ret.Get(0).(func(model.Permission) error); ok {
		r0 = rf(item)
	} else {
		r0 = ret.Error(0)
	}

	return r0
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

// PerformTransaction provides a mock function with given fields: _a0
func (_m *Storage) PerformTransaction(_a0 func(storage.TransactionContext) error) error {
	ret := _m.Called(_a0)

	var r0 error
	if rf, ok := ret.Get(0).(func(func(storage.TransactionContext) error) error); ok {
		r0 = rf(_a0)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// RegisterStorageListener provides a mock function with given fields: storageListener
func (_m *Storage) RegisterStorageListener(storageListener storage.Listener) {
	_m.Called(storageListener)
}

// SaveDevice provides a mock function with given fields: context, device
func (_m *Storage) SaveDevice(context storage.TransactionContext, device *model.Device) error {
	ret := _m.Called(context, device)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, *model.Device) error); ok {
		r0 = rf(context, device)
	} else {
		r0 = ret.Error(0)
	}

	return r0
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

// UpdateAppOrgGroup provides a mock function with given fields: item
func (_m *Storage) UpdateAppOrgGroup(item model.AppOrgGroup) error {
	ret := _m.Called(item)

	var r0 error
	if rf, ok := ret.Get(0).(func(model.AppOrgGroup) error); ok {
		r0 = rf(item)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateAppOrgRole provides a mock function with given fields: item
func (_m *Storage) UpdateAppOrgRole(item model.AppOrgRole) error {
	ret := _m.Called(item)

	var r0 error
	if rf, ok := ret.Get(0).(func(model.AppOrgRole) error); ok {
		r0 = rf(item)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateCredential provides a mock function with given fields: context, creds
func (_m *Storage) UpdateCredential(context storage.TransactionContext, creds *model.Credential) error {
	ret := _m.Called(context, creds)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, *model.Credential) error); ok {
		r0 = rf(context, creds)
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

// UpdatePermission provides a mock function with given fields: item
func (_m *Storage) UpdatePermission(item model.Permission) error {
	ret := _m.Called(item)

	var r0 error
	if rf, ok := ret.Get(0).(func(model.Permission) error); ok {
		r0 = rf(item)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateProfile provides a mock function with given fields: accountID, profile
func (_m *Storage) UpdateProfile(accountID string, profile *model.Profile) error {
	ret := _m.Called(accountID, profile)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, *model.Profile) error); ok {
		r0 = rf(accountID, profile)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
