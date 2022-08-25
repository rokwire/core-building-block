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

// CountAccountsByGroupID provides a mock function with given fields: groupID
func (_m *Storage) CountAccountsByGroupID(groupID string) (*int64, error) {
	ret := _m.Called(groupID)

	var r0 *int64
	if rf, ok := ret.Get(0).(func(string) *int64); ok {
		r0 = rf(groupID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*int64)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(groupID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CountAccountsByRoleID provides a mock function with given fields: roleID
func (_m *Storage) CountAccountsByRoleID(roleID string) (*int64, error) {
	ret := _m.Called(roleID)

	var r0 *int64
	if rf, ok := ret.Get(0).(func(string) *int64); ok {
		r0 = rf(roleID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*int64)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(roleID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// CountGroupsByRoleID provides a mock function with given fields: roleID
func (_m *Storage) CountGroupsByRoleID(roleID string) (*int64, error) {
	ret := _m.Called(roleID)

	var r0 *int64
	if rf, ok := ret.Get(0).(func(string) *int64); ok {
		r0 = rf(roleID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*int64)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(roleID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
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

// DeleteAccountPermissions provides a mock function with given fields: context, accountID, hasPermissions, permissions
func (_m *Storage) DeleteAccountPermissions(context storage.TransactionContext, accountID string, hasPermissions bool, permissions []model.Permission) error {
	ret := _m.Called(context, accountID, hasPermissions, permissions)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string, bool, []model.Permission) error); ok {
		r0 = rf(context, accountID, hasPermissions, permissions)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteAccountRoles provides a mock function with given fields: context, accountID, hasPermissions, roleIDs
func (_m *Storage) DeleteAccountRoles(context storage.TransactionContext, accountID string, hasPermissions bool, roleIDs []string) error {
	ret := _m.Called(context, accountID, hasPermissions, roleIDs)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string, bool, []string) error); ok {
		r0 = rf(context, accountID, hasPermissions, roleIDs)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteAppConfig provides a mock function with given fields: ID
func (_m *Storage) DeleteAppConfig(ID string) error {
	ret := _m.Called(ID)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(ID)
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

// DeleteLoginSessionByID provides a mock function with given fields: context, id
func (_m *Storage) DeleteLoginSessionByID(context storage.TransactionContext, id string) error {
	ret := _m.Called(context, id)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string) error); ok {
		r0 = rf(context, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteLoginSessionsByIdentifier provides a mock function with given fields: context, identifier
func (_m *Storage) DeleteLoginSessionsByIdentifier(context storage.TransactionContext, identifier string) error {
	ret := _m.Called(context, identifier)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string) error); ok {
		r0 = rf(context, identifier)
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

// FindAccounts provides a mock function with given fields: limit, offset, appID, orgID, accountID, firstName, lastName, authType, authTypeIdentifier, hasPermissions, permissions, roleIDs, groupIDs
func (_m *Storage) FindAccounts(limit int, offset int, appID string, orgID string, accountID *string, firstName *string, lastName *string, authType *string, authTypeIdentifier *string, hasPermissions *bool, permissions []string, roleIDs []string, groupIDs []string) ([]model.Account, error) {
	ret := _m.Called(limit, offset, appID, orgID, accountID, firstName, lastName, authType, authTypeIdentifier, hasPermissions, permissions, roleIDs, groupIDs)

	var r0 []model.Account
	if rf, ok := ret.Get(0).(func(int, int, string, string, *string, *string, *string, *string, *string, *bool, []string, []string, []string) []model.Account); ok {
		r0 = rf(limit, offset, appID, orgID, accountID, firstName, lastName, authType, authTypeIdentifier, hasPermissions, permissions, roleIDs, groupIDs)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.Account)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(int, int, string, string, *string, *string, *string, *string, *string, *bool, []string, []string, []string) error); ok {
		r1 = rf(limit, offset, appID, orgID, accountID, firstName, lastName, authType, authTypeIdentifier, hasPermissions, permissions, roleIDs, groupIDs)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindAccountsByAccountID provides a mock function with given fields: appID, orgID, accountIDs
func (_m *Storage) FindAccountsByAccountID(appID string, orgID string, accountIDs []string) ([]model.Account, error) {
	ret := _m.Called(appID, orgID, accountIDs)

	var r0 []model.Account
	if rf, ok := ret.Get(0).(func(string, string, []string) []model.Account); ok {
		r0 = rf(appID, orgID, accountIDs)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.Account)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string, []string) error); ok {
		r1 = rf(appID, orgID, accountIDs)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindAppConfigByID provides a mock function with given fields: ID
func (_m *Storage) FindAppConfigByID(ID string) (*model.ApplicationConfig, error) {
	ret := _m.Called(ID)

	var r0 *model.ApplicationConfig
	if rf, ok := ret.Get(0).(func(string) *model.ApplicationConfig); ok {
		r0 = rf(ID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.ApplicationConfig)
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

// FindAppConfigByVersion provides a mock function with given fields: appTypeIdentifier, appOrgID, versionNumbers
func (_m *Storage) FindAppConfigByVersion(appTypeIdentifier string, appOrgID *string, versionNumbers model.VersionNumbers) (*model.ApplicationConfig, error) {
	ret := _m.Called(appTypeIdentifier, appOrgID, versionNumbers)

	var r0 *model.ApplicationConfig
	if rf, ok := ret.Get(0).(func(string, *string, model.VersionNumbers) *model.ApplicationConfig); ok {
		r0 = rf(appTypeIdentifier, appOrgID, versionNumbers)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.ApplicationConfig)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, *string, model.VersionNumbers) error); ok {
		r1 = rf(appTypeIdentifier, appOrgID, versionNumbers)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindAppConfigs provides a mock function with given fields: appTypeIdentifier, appOrgID, versionNumbers
func (_m *Storage) FindAppConfigs(appTypeIdentifier string, appOrgID *string, versionNumbers *model.VersionNumbers) ([]model.ApplicationConfig, error) {
	ret := _m.Called(appTypeIdentifier, appOrgID, versionNumbers)

	var r0 []model.ApplicationConfig
	if rf, ok := ret.Get(0).(func(string, *string, *model.VersionNumbers) []model.ApplicationConfig); ok {
		r0 = rf(appTypeIdentifier, appOrgID, versionNumbers)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.ApplicationConfig)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, *string, *model.VersionNumbers) error); ok {
		r1 = rf(appTypeIdentifier, appOrgID, versionNumbers)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindAppOrgGroup provides a mock function with given fields: id, appOrgID
func (_m *Storage) FindAppOrgGroup(id string, appOrgID string) (*model.AppOrgGroup, error) {
	ret := _m.Called(id, appOrgID)

	var r0 *model.AppOrgGroup
	if rf, ok := ret.Get(0).(func(string, string) *model.AppOrgGroup); ok {
		r0 = rf(id, appOrgID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.AppOrgGroup)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string) error); ok {
		r1 = rf(id, appOrgID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindAppOrgGroups provides a mock function with given fields: appOrgID
func (_m *Storage) FindAppOrgGroups(appOrgID string) ([]model.AppOrgGroup, error) {
	ret := _m.Called(appOrgID)

	var r0 []model.AppOrgGroup
	if rf, ok := ret.Get(0).(func(string) []model.AppOrgGroup); ok {
		r0 = rf(appOrgID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.AppOrgGroup)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(appOrgID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindAppOrgGroupsByIDs provides a mock function with given fields: context, ids, appOrgID
func (_m *Storage) FindAppOrgGroupsByIDs(context storage.TransactionContext, ids []string, appOrgID string) ([]model.AppOrgGroup, error) {
	ret := _m.Called(context, ids, appOrgID)

	var r0 []model.AppOrgGroup
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, []string, string) []model.AppOrgGroup); ok {
		r0 = rf(context, ids, appOrgID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.AppOrgGroup)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(storage.TransactionContext, []string, string) error); ok {
		r1 = rf(context, ids, appOrgID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindAppOrgRole provides a mock function with given fields: id, appOrgID
func (_m *Storage) FindAppOrgRole(id string, appOrgID string) (*model.AppOrgRole, error) {
	ret := _m.Called(id, appOrgID)

	var r0 *model.AppOrgRole
	if rf, ok := ret.Get(0).(func(string, string) *model.AppOrgRole); ok {
		r0 = rf(id, appOrgID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.AppOrgRole)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string) error); ok {
		r1 = rf(id, appOrgID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindAppOrgRoles provides a mock function with given fields: appOrgID
func (_m *Storage) FindAppOrgRoles(appOrgID string) ([]model.AppOrgRole, error) {
	ret := _m.Called(appOrgID)

	var r0 []model.AppOrgRole
	if rf, ok := ret.Get(0).(func(string) []model.AppOrgRole); ok {
		r0 = rf(appOrgID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.AppOrgRole)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(appOrgID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindAppOrgRolesByIDs provides a mock function with given fields: context, ids, appOrgID
func (_m *Storage) FindAppOrgRolesByIDs(context storage.TransactionContext, ids []string, appOrgID string) ([]model.AppOrgRole, error) {
	ret := _m.Called(context, ids, appOrgID)

	var r0 []model.AppOrgRole
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, []string, string) []model.AppOrgRole); ok {
		r0 = rf(context, ids, appOrgID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.AppOrgRole)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(storage.TransactionContext, []string, string) error); ok {
		r1 = rf(context, ids, appOrgID)
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

// FindApplicationOrganization provides a mock function with given fields: appID, orgID
func (_m *Storage) FindApplicationOrganization(appID string, orgID string) (*model.ApplicationOrganization, error) {
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

// FindApplicationType provides a mock function with given fields: id
func (_m *Storage) FindApplicationType(id string) (*model.ApplicationType, error) {
	ret := _m.Called(id)

	var r0 *model.ApplicationType
	if rf, ok := ret.Get(0).(func(string) *model.ApplicationType); ok {
		r0 = rf(id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.ApplicationType)
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

// FindApplicationsOrganizationsByOrgID provides a mock function with given fields: orgID
func (_m *Storage) FindApplicationsOrganizationsByOrgID(orgID string) ([]model.ApplicationOrganization, error) {
	ret := _m.Called(orgID)

	var r0 []model.ApplicationOrganization
	if rf, ok := ret.Get(0).(func(string) []model.ApplicationOrganization); ok {
		r0 = rf(orgID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.ApplicationOrganization)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(orgID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindAuthType provides a mock function with given fields: codeOrID
func (_m *Storage) FindAuthType(codeOrID string) (*model.AuthType, error) {
	ret := _m.Called(codeOrID)

	var r0 *model.AuthType
	if rf, ok := ret.Get(0).(func(string) *model.AuthType); ok {
		r0 = rf(codeOrID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.AuthType)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(codeOrID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindAuthTypes provides a mock function with given fields:
func (_m *Storage) FindAuthTypes() ([]model.AuthType, error) {
	ret := _m.Called()

	var r0 []model.AuthType
	if rf, ok := ret.Get(0).(func() []model.AuthType); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.AuthType)
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

// FindLoginSessionsByParams provides a mock function with given fields: appID, orgID, sessionID, identifier, accountAuthTypeIdentifier, appTypeID, appTypeIdentifier, anonymous, deviceID, ipAddress
func (_m *Storage) FindLoginSessionsByParams(appID string, orgID string, sessionID *string, identifier *string, accountAuthTypeIdentifier *string, appTypeID *string, appTypeIdentifier *string, anonymous *bool, deviceID *string, ipAddress *string) ([]model.LoginSession, error) {
	ret := _m.Called(appID, orgID, sessionID, identifier, accountAuthTypeIdentifier, appTypeID, appTypeIdentifier, anonymous, deviceID, ipAddress)

	var r0 []model.LoginSession
	if rf, ok := ret.Get(0).(func(string, string, *string, *string, *string, *string, *string, *bool, *string, *string) []model.LoginSession); ok {
		r0 = rf(appID, orgID, sessionID, identifier, accountAuthTypeIdentifier, appTypeID, appTypeIdentifier, anonymous, deviceID, ipAddress)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.LoginSession)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string, *string, *string, *string, *string, *string, *bool, *string, *string) error); ok {
		r1 = rf(appID, orgID, sessionID, identifier, accountAuthTypeIdentifier, appTypeID, appTypeIdentifier, anonymous, deviceID, ipAddress)
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

// FindOrganizations provides a mock function with given fields:
func (_m *Storage) FindOrganizations() ([]model.Organization, error) {
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

// FindPermissionsByName provides a mock function with given fields: context, names
func (_m *Storage) FindPermissionsByName(context storage.TransactionContext, names []string) ([]model.Permission, error) {
	ret := _m.Called(context, names)

	var r0 []model.Permission
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, []string) []model.Permission); ok {
		r0 = rf(context, names)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.Permission)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(storage.TransactionContext, []string) error); ok {
		r1 = rf(context, names)
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

// FindSystemOrganization provides a mock function with given fields:
func (_m *Storage) FindSystemOrganization() (*model.Organization, error) {
	ret := _m.Called()

	var r0 *model.Organization
	if rf, ok := ret.Get(0).(func() *model.Organization); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Organization)
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

// FindWebhookConfig provides a mock function with given fields:
func (_m *Storage) FindWebhookConfig() (*model.WebhookConfig, error) {
	ret := _m.Called()

	var r0 *model.WebhookConfig
	if rf, ok := ret.Get(0).(func() *model.WebhookConfig); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.WebhookConfig)
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

// InsertAPIKey provides a mock function with given fields: context, apiKey
func (_m *Storage) InsertAPIKey(context storage.TransactionContext, apiKey model.APIKey) (*model.APIKey, error) {
	ret := _m.Called(context, apiKey)

	var r0 *model.APIKey
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, model.APIKey) *model.APIKey); ok {
		r0 = rf(context, apiKey)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.APIKey)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(storage.TransactionContext, model.APIKey) error); ok {
		r1 = rf(context, apiKey)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// InsertAccountPermissions provides a mock function with given fields: context, accountID, permissions
func (_m *Storage) InsertAccountPermissions(context storage.TransactionContext, accountID string, permissions []model.Permission) error {
	ret := _m.Called(context, accountID, permissions)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string, []model.Permission) error); ok {
		r0 = rf(context, accountID, permissions)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// InsertAccountRoles provides a mock function with given fields: context, accountID, appOrgID, roles
func (_m *Storage) InsertAccountRoles(context storage.TransactionContext, accountID string, appOrgID string, roles []model.AccountRole) error {
	ret := _m.Called(context, accountID, appOrgID, roles)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string, string, []model.AccountRole) error); ok {
		r0 = rf(context, accountID, appOrgID, roles)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// InsertAccountsGroup provides a mock function with given fields: group, accounts
func (_m *Storage) InsertAccountsGroup(group model.AccountGroup, accounts []model.Account) error {
	ret := _m.Called(group, accounts)

	var r0 error
	if rf, ok := ret.Get(0).(func(model.AccountGroup, []model.Account) error); ok {
		r0 = rf(group, accounts)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// InsertAppConfig provides a mock function with given fields: item
func (_m *Storage) InsertAppConfig(item model.ApplicationConfig) (*model.ApplicationConfig, error) {
	ret := _m.Called(item)

	var r0 *model.ApplicationConfig
	if rf, ok := ret.Get(0).(func(model.ApplicationConfig) *model.ApplicationConfig); ok {
		r0 = rf(item)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.ApplicationConfig)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(model.ApplicationConfig) error); ok {
		r1 = rf(item)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// InsertAppOrgGroup provides a mock function with given fields: context, item
func (_m *Storage) InsertAppOrgGroup(context storage.TransactionContext, item model.AppOrgGroup) error {
	ret := _m.Called(context, item)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, model.AppOrgGroup) error); ok {
		r0 = rf(context, item)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// InsertAppOrgRole provides a mock function with given fields: context, item
func (_m *Storage) InsertAppOrgRole(context storage.TransactionContext, item model.AppOrgRole) error {
	ret := _m.Called(context, item)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, model.AppOrgRole) error); ok {
		r0 = rf(context, item)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// InsertAppOrgRolePermissions provides a mock function with given fields: context, roleID, permissionNames
func (_m *Storage) InsertAppOrgRolePermissions(context storage.TransactionContext, roleID string, permissionNames []model.Permission) error {
	ret := _m.Called(context, roleID, permissionNames)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string, []model.Permission) error); ok {
		r0 = rf(context, roleID, permissionNames)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// InsertApplication provides a mock function with given fields: context, application
func (_m *Storage) InsertApplication(context storage.TransactionContext, application model.Application) (*model.Application, error) {
	ret := _m.Called(context, application)

	var r0 *model.Application
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, model.Application) *model.Application); ok {
		r0 = rf(context, application)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Application)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(storage.TransactionContext, model.Application) error); ok {
		r1 = rf(context, application)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// InsertApplicationOrganization provides a mock function with given fields: context, applicationOrganization
func (_m *Storage) InsertApplicationOrganization(context storage.TransactionContext, applicationOrganization model.ApplicationOrganization) (*model.ApplicationOrganization, error) {
	ret := _m.Called(context, applicationOrganization)

	var r0 *model.ApplicationOrganization
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, model.ApplicationOrganization) *model.ApplicationOrganization); ok {
		r0 = rf(context, applicationOrganization)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.ApplicationOrganization)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(storage.TransactionContext, model.ApplicationOrganization) error); ok {
		r1 = rf(context, applicationOrganization)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// InsertAuthType provides a mock function with given fields: context, authType
func (_m *Storage) InsertAuthType(context storage.TransactionContext, authType model.AuthType) (*model.AuthType, error) {
	ret := _m.Called(context, authType)

	var r0 *model.AuthType
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, model.AuthType) *model.AuthType); ok {
		r0 = rf(context, authType)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.AuthType)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(storage.TransactionContext, model.AuthType) error); ok {
		r1 = rf(context, authType)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// InsertOrganization provides a mock function with given fields: context, organization
func (_m *Storage) InsertOrganization(context storage.TransactionContext, organization model.Organization) (*model.Organization, error) {
	ret := _m.Called(context, organization)

	var r0 *model.Organization
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, model.Organization) *model.Organization); ok {
		r0 = rf(context, organization)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Organization)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(storage.TransactionContext, model.Organization) error); ok {
		r1 = rf(context, organization)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// InsertPermission provides a mock function with given fields: context, item
func (_m *Storage) InsertPermission(context storage.TransactionContext, item model.Permission) error {
	ret := _m.Called(context, item)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, model.Permission) error); ok {
		r0 = rf(context, item)
	} else {
		r0 = ret.Error(0)
	}

	return r0
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

// RemoveAccountsGroup provides a mock function with given fields: groupID, accounts, hasPermissions
func (_m *Storage) RemoveAccountsGroup(groupID string, accounts []model.Account, hasPermissions []bool) error {
	ret := _m.Called(groupID, accounts, hasPermissions)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, []model.Account, []bool) error); ok {
		r0 = rf(groupID, accounts, hasPermissions)
	} else {
		r0 = ret.Error(0)
	}

	return r0
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

// UpdateAccountSystemConfigs provides a mock function with given fields: context, accountID, configs
func (_m *Storage) UpdateAccountSystemConfigs(context storage.TransactionContext, accountID string, configs map[string]interface{}) error {
	ret := _m.Called(context, accountID, configs)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string, map[string]interface{}) error); ok {
		r0 = rf(context, accountID, configs)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateAppConfig provides a mock function with given fields: ID, appType, appOrg, version, data, vcsManaged
func (_m *Storage) UpdateAppConfig(ID string, appType model.ApplicationType, appOrg *model.ApplicationOrganization, version model.Version, data map[string]interface{}, vcsManaged bool) error {
	ret := _m.Called(ID, appType, appOrg, version, data, vcsManaged)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, model.ApplicationType, *model.ApplicationOrganization, model.Version, map[string]interface{}, bool) error); ok {
		r0 = rf(ID, appType, appOrg, version, data, vcsManaged)
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

// UpdateAuthTypes provides a mock function with given fields: ID, code, description, isExternal, isAnonymous, useCredentials, ignoreMFA, params
func (_m *Storage) UpdateAuthTypes(ID string, code string, description string, isExternal bool, isAnonymous bool, useCredentials bool, ignoreMFA bool, params map[string]interface{}) error {
	ret := _m.Called(ID, code, description, isExternal, isAnonymous, useCredentials, ignoreMFA, params)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string, string, bool, bool, bool, bool, map[string]interface{}) error); ok {
		r0 = rf(ID, code, description, isExternal, isAnonymous, useCredentials, ignoreMFA, params)
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

// UpdateProfile provides a mock function with given fields: context, profile
func (_m *Storage) UpdateProfile(context storage.TransactionContext, profile model.Profile) error {
	ret := _m.Called(context, profile)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, model.Profile) error); ok {
		r0 = rf(context, profile)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateWebhookConfig provides a mock function with given fields: webhookConfig
func (_m *Storage) UpdateWebhookConfig(webhookConfig model.WebhookConfig) error {
	ret := _m.Called(webhookConfig)

	var r0 error
	if rf, ok := ret.Get(0).(func(model.WebhookConfig) error); ok {
		r0 = rf(webhookConfig)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}
