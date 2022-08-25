// Code generated by mockery v2.14.0. DO NOT EDIT.

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

// DeleteAPIKey provides a mock function with given fields: ID
func (_m *Storage) DeleteAPIKey(ID string) error {
	ret := _m.Called(ID)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(ID)
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

// DeleteAccountAuthType provides a mock function with given fields: context, item
func (_m *Storage) DeleteAccountAuthType(context storage.TransactionContext, item model.AccountAuthType) error {
	ret := _m.Called(context, item)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, model.AccountAuthType) error); ok {
		r0 = rf(context, item)
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

// DeleteLoginSession provides a mock function with given fields: context, id
func (_m *Storage) DeleteLoginSession(context storage.TransactionContext, id string) error {
	ret := _m.Called(context, id)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string) error); ok {
		r0 = rf(context, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteLoginSessionsByAccountAuthTypeID provides a mock function with given fields: context, id
func (_m *Storage) DeleteLoginSessionsByAccountAuthTypeID(context storage.TransactionContext, id string) error {
	ret := _m.Called(context, id)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string) error); ok {
		r0 = rf(context, id)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteLoginSessionsByIDs provides a mock function with given fields: context, ids
func (_m *Storage) DeleteLoginSessionsByIDs(context storage.TransactionContext, ids []string) error {
	ret := _m.Called(context, ids)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, []string) error); ok {
		r0 = rf(context, ids)
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

// DeleteMFAExpiredSessions provides a mock function with given fields:
func (_m *Storage) DeleteMFAExpiredSessions() error {
	ret := _m.Called()

	var r0 error
	if rf, ok := ret.Get(0).(func() error); ok {
		r0 = rf()
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteMFAType provides a mock function with given fields: context, accountID, identifier, mfaType
func (_m *Storage) DeleteMFAType(context storage.TransactionContext, accountID string, identifier string, mfaType string) error {
	ret := _m.Called(context, accountID, identifier, mfaType)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string, string, string) error); ok {
		r0 = rf(context, accountID, identifier, mfaType)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteServiceAccount provides a mock function with given fields: accountID, appID, orgID
func (_m *Storage) DeleteServiceAccount(accountID string, appID string, orgID string) error {
	ret := _m.Called(accountID, appID, orgID)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string, string) error); ok {
		r0 = rf(accountID, appID, orgID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteServiceAccountCredential provides a mock function with given fields: accountID, credID
func (_m *Storage) DeleteServiceAccountCredential(accountID string, credID string) error {
	ret := _m.Called(accountID, credID)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string) error); ok {
		r0 = rf(accountID, credID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteServiceAccounts provides a mock function with given fields: accountID
func (_m *Storage) DeleteServiceAccounts(accountID string) error {
	ret := _m.Called(accountID)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(accountID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteServiceAuthorization provides a mock function with given fields: userID, orgID
func (_m *Storage) DeleteServiceAuthorization(userID string, orgID string) error {
	ret := _m.Called(userID, orgID)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, string) error); ok {
		r0 = rf(userID, orgID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// DeleteServiceReg provides a mock function with given fields: serviceID
func (_m *Storage) DeleteServiceReg(serviceID string) error {
	ret := _m.Called(serviceID)

	var r0 error
	if rf, ok := ret.Get(0).(func(string) error); ok {
		r0 = rf(serviceID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// FindAccount provides a mock function with given fields: context, appOrgID, authTypeID, accountAuthTypeIdentifier
func (_m *Storage) FindAccount(context storage.TransactionContext, appOrgID string, authTypeID string, accountAuthTypeIdentifier string) (*model.Account, error) {
	ret := _m.Called(context, appOrgID, authTypeID, accountAuthTypeIdentifier)

	var r0 *model.Account
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string, string, string) *model.Account); ok {
		r0 = rf(context, appOrgID, authTypeID, accountAuthTypeIdentifier)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Account)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(storage.TransactionContext, string, string, string) error); ok {
		r1 = rf(context, appOrgID, authTypeID, accountAuthTypeIdentifier)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindAccountByAuthTypeID provides a mock function with given fields: context, id
func (_m *Storage) FindAccountByAuthTypeID(context storage.TransactionContext, id string) (*model.Account, error) {
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

// FindAndUpdateLoginSession provides a mock function with given fields: context, id
func (_m *Storage) FindAndUpdateLoginSession(context storage.TransactionContext, id string) (*model.LoginSession, error) {
	ret := _m.Called(context, id)

	var r0 *model.LoginSession
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string) *model.LoginSession); ok {
		r0 = rf(context, id)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.LoginSession)
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

// FindApplicationsOrganizations provides a mock function with given fields:
func (_m *Storage) FindApplicationsOrganizations() ([]model.ApplicationOrganization, error) {
	ret := _m.Called()

	var r0 []model.ApplicationOrganization
	if rf, ok := ret.Get(0).(func() []model.ApplicationOrganization); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.ApplicationOrganization)
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

// FindDevice provides a mock function with given fields: context, deviceID, accountID
func (_m *Storage) FindDevice(context storage.TransactionContext, deviceID string, accountID string) (*model.Device, error) {
	ret := _m.Called(context, deviceID, accountID)

	var r0 *model.Device
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string, string) *model.Device); ok {
		r0 = rf(context, deviceID, accountID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Device)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(storage.TransactionContext, string, string) error); ok {
		r1 = rf(context, deviceID, accountID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindLoginSession provides a mock function with given fields: refreshToken
func (_m *Storage) FindLoginSession(refreshToken string) (*model.LoginSession, error) {
	ret := _m.Called(refreshToken)

	var r0 *model.LoginSession
	if rf, ok := ret.Get(0).(func(string) *model.LoginSession); ok {
		r0 = rf(refreshToken)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.LoginSession)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(refreshToken)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindLoginSessions provides a mock function with given fields: context, identifier
func (_m *Storage) FindLoginSessions(context storage.TransactionContext, identifier string) ([]model.LoginSession, error) {
	ret := _m.Called(context, identifier)

	var r0 []model.LoginSession
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string) []model.LoginSession); ok {
		r0 = rf(context, identifier)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.LoginSession)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(storage.TransactionContext, string) error); ok {
		r1 = rf(context, identifier)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindMFAType provides a mock function with given fields: context, accountID, identifier, mfaType
func (_m *Storage) FindMFAType(context storage.TransactionContext, accountID string, identifier string, mfaType string) (*model.MFAType, error) {
	ret := _m.Called(context, accountID, identifier, mfaType)

	var r0 *model.MFAType
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string, string, string) *model.MFAType); ok {
		r0 = rf(context, accountID, identifier, mfaType)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.MFAType)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(storage.TransactionContext, string, string, string) error); ok {
		r1 = rf(context, accountID, identifier, mfaType)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindMFATypes provides a mock function with given fields: accountID
func (_m *Storage) FindMFATypes(accountID string) ([]model.MFAType, error) {
	ret := _m.Called(accountID)

	var r0 []model.MFAType
	if rf, ok := ret.Get(0).(func(string) []model.MFAType); ok {
		r0 = rf(accountID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.MFAType)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(accountID)
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

// FindPermissions provides a mock function with given fields: context, ids
func (_m *Storage) FindPermissions(context storage.TransactionContext, ids []string) ([]model.Permission, error) {
	ret := _m.Called(context, ids)

	var r0 []model.Permission
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, []string) []model.Permission); ok {
		r0 = rf(context, ids)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.Permission)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(storage.TransactionContext, []string) error); ok {
		r1 = rf(context, ids)
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

// FindProfiles provides a mock function with given fields: appID, authTypeID, accountAuthTypeIdentifier
func (_m *Storage) FindProfiles(appID string, authTypeID string, accountAuthTypeIdentifier string) ([]model.Profile, error) {
	ret := _m.Called(appID, authTypeID, accountAuthTypeIdentifier)

	var r0 []model.Profile
	if rf, ok := ret.Get(0).(func(string, string, string) []model.Profile); ok {
		r0 = rf(appID, authTypeID, accountAuthTypeIdentifier)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.Profile)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string, string) error); ok {
		r1 = rf(appID, authTypeID, accountAuthTypeIdentifier)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindServiceAccount provides a mock function with given fields: context, accountID, appID, orgID
func (_m *Storage) FindServiceAccount(context storage.TransactionContext, accountID string, appID string, orgID string) (*model.ServiceAccount, error) {
	ret := _m.Called(context, accountID, appID, orgID)

	var r0 *model.ServiceAccount
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string, string, string) *model.ServiceAccount); ok {
		r0 = rf(context, accountID, appID, orgID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.ServiceAccount)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(storage.TransactionContext, string, string, string) error); ok {
		r1 = rf(context, accountID, appID, orgID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindServiceAccounts provides a mock function with given fields: params
func (_m *Storage) FindServiceAccounts(params map[string]interface{}) ([]model.ServiceAccount, error) {
	ret := _m.Called(params)

	var r0 []model.ServiceAccount
	if rf, ok := ret.Get(0).(func(map[string]interface{}) []model.ServiceAccount); ok {
		r0 = rf(params)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.ServiceAccount)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(map[string]interface{}) error); ok {
		r1 = rf(params)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindServiceAuthorization provides a mock function with given fields: userID, orgID
func (_m *Storage) FindServiceAuthorization(userID string, orgID string) (*model.ServiceAuthorization, error) {
	ret := _m.Called(userID, orgID)

	var r0 *model.ServiceAuthorization
	if rf, ok := ret.Get(0).(func(string, string) *model.ServiceAuthorization); ok {
		r0 = rf(userID, orgID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.ServiceAuthorization)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string, string) error); ok {
		r1 = rf(userID, orgID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindServiceReg provides a mock function with given fields: serviceID
func (_m *Storage) FindServiceReg(serviceID string) (*model.ServiceReg, error) {
	ret := _m.Called(serviceID)

	var r0 *model.ServiceReg
	if rf, ok := ret.Get(0).(func(string) *model.ServiceReg); ok {
		r0 = rf(serviceID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.ServiceReg)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(serviceID)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// FindServiceRegs provides a mock function with given fields: serviceIDs
func (_m *Storage) FindServiceRegs(serviceIDs []string) []model.ServiceReg {
	ret := _m.Called(serviceIDs)

	var r0 []model.ServiceReg
	if rf, ok := ret.Get(0).(func([]string) []model.ServiceReg); ok {
		r0 = rf(serviceIDs)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.ServiceReg)
		}
	}

	return r0
}

// FindSessionsLazy provides a mock function with given fields: appID, orgID
func (_m *Storage) FindSessionsLazy(appID string, orgID string) ([]model.LoginSession, error) {
	ret := _m.Called(appID, orgID)

	var r0 []model.LoginSession
	if rf, ok := ret.Get(0).(func(string, string) []model.LoginSession); ok {
		r0 = rf(appID, orgID)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.LoginSession)
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

// InsertAccount provides a mock function with given fields: context, account
func (_m *Storage) InsertAccount(context storage.TransactionContext, account model.Account) (*model.Account, error) {
	ret := _m.Called(context, account)

	var r0 *model.Account
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, model.Account) *model.Account); ok {
		r0 = rf(context, account)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Account)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(storage.TransactionContext, model.Account) error); ok {
		r1 = rf(context, account)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// InsertAccountAuthType provides a mock function with given fields: item
func (_m *Storage) InsertAccountAuthType(item model.AccountAuthType) error {
	ret := _m.Called(item)

	var r0 error
	if rf, ok := ret.Get(0).(func(model.AccountAuthType) error); ok {
		r0 = rf(item)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// InsertAccountGroups provides a mock function with given fields: context, accountID, appOrgID, groups
func (_m *Storage) InsertAccountGroups(context storage.TransactionContext, accountID string, appOrgID string, groups []model.AccountGroup) error {
	ret := _m.Called(context, accountID, appOrgID, groups)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string, string, []model.AccountGroup) error); ok {
		r0 = rf(context, accountID, appOrgID, groups)
	} else {
		r0 = ret.Error(0)
	}

	return r0
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

// InsertCredential provides a mock function with given fields: context, creds
func (_m *Storage) InsertCredential(context storage.TransactionContext, creds *model.Credential) error {
	ret := _m.Called(context, creds)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, *model.Credential) error); ok {
		r0 = rf(context, creds)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// InsertDevice provides a mock function with given fields: context, device
func (_m *Storage) InsertDevice(context storage.TransactionContext, device model.Device) (*model.Device, error) {
	ret := _m.Called(context, device)

	var r0 *model.Device
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, model.Device) *model.Device); ok {
		r0 = rf(context, device)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.Device)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(storage.TransactionContext, model.Device) error); ok {
		r1 = rf(context, device)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// InsertLoginSession provides a mock function with given fields: context, session
func (_m *Storage) InsertLoginSession(context storage.TransactionContext, session model.LoginSession) error {
	ret := _m.Called(context, session)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, model.LoginSession) error); ok {
		r0 = rf(context, session)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// InsertMFAType provides a mock function with given fields: context, mfa, accountID
func (_m *Storage) InsertMFAType(context storage.TransactionContext, mfa *model.MFAType, accountID string) error {
	ret := _m.Called(context, mfa, accountID)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, *model.MFAType, string) error); ok {
		r0 = rf(context, mfa, accountID)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// InsertServiceAccount provides a mock function with given fields: account
func (_m *Storage) InsertServiceAccount(account *model.ServiceAccount) error {
	ret := _m.Called(account)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.ServiceAccount) error); ok {
		r0 = rf(account)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// InsertServiceAccountCredential provides a mock function with given fields: accountID, creds
func (_m *Storage) InsertServiceAccountCredential(accountID string, creds *model.ServiceAccountCredential) error {
	ret := _m.Called(accountID, creds)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, *model.ServiceAccountCredential) error); ok {
		r0 = rf(accountID, creds)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// InsertServiceReg provides a mock function with given fields: reg
func (_m *Storage) InsertServiceReg(reg *model.ServiceReg) error {
	ret := _m.Called(reg)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.ServiceReg) error); ok {
		r0 = rf(reg)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// LoadAPIKeys provides a mock function with given fields:
func (_m *Storage) LoadAPIKeys() ([]model.APIKey, error) {
	ret := _m.Called()

	var r0 []model.APIKey
	if rf, ok := ret.Get(0).(func() []model.APIKey); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.APIKey)
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

// LoadIdentityProviders provides a mock function with given fields:
func (_m *Storage) LoadIdentityProviders() ([]model.IdentityProvider, error) {
	ret := _m.Called()

	var r0 []model.IdentityProvider
	if rf, ok := ret.Get(0).(func() []model.IdentityProvider); ok {
		r0 = rf()
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).([]model.IdentityProvider)
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

// SaveAccount provides a mock function with given fields: context, account
func (_m *Storage) SaveAccount(context storage.TransactionContext, account *model.Account) error {
	ret := _m.Called(context, account)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, *model.Account) error); ok {
		r0 = rf(context, account)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SaveServiceAuthorization provides a mock function with given fields: authorization
func (_m *Storage) SaveServiceAuthorization(authorization *model.ServiceAuthorization) error {
	ret := _m.Called(authorization)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.ServiceAuthorization) error); ok {
		r0 = rf(authorization)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// SaveServiceReg provides a mock function with given fields: reg
func (_m *Storage) SaveServiceReg(reg *model.ServiceReg) error {
	ret := _m.Called(reg)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.ServiceReg) error); ok {
		r0 = rf(reg)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateAPIKey provides a mock function with given fields: apiKey
func (_m *Storage) UpdateAPIKey(apiKey model.APIKey) error {
	ret := _m.Called(apiKey)

	var r0 error
	if rf, ok := ret.Get(0).(func(model.APIKey) error); ok {
		r0 = rf(apiKey)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateAccountAuthType provides a mock function with given fields: item
func (_m *Storage) UpdateAccountAuthType(item model.AccountAuthType) error {
	ret := _m.Called(item)

	var r0 error
	if rf, ok := ret.Get(0).(func(model.AccountAuthType) error); ok {
		r0 = rf(item)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateAccountExternalIDs provides a mock function with given fields: accountID, externalIDs
func (_m *Storage) UpdateAccountExternalIDs(accountID string, externalIDs map[string]string) error {
	ret := _m.Called(accountID, externalIDs)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, map[string]string) error); ok {
		r0 = rf(accountID, externalIDs)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateAccountGroups provides a mock function with given fields: context, accountID, hasPermissions, groups
func (_m *Storage) UpdateAccountGroups(context storage.TransactionContext, accountID string, hasPermissions bool, groups []model.AccountGroup) error {
	ret := _m.Called(context, accountID, hasPermissions, groups)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string, bool, []model.AccountGroup) error); ok {
		r0 = rf(context, accountID, hasPermissions, groups)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateAccountPermissions provides a mock function with given fields: context, accountID, hasPermissions, permissions
func (_m *Storage) UpdateAccountPermissions(context storage.TransactionContext, accountID string, hasPermissions bool, permissions []model.Permission) error {
	ret := _m.Called(context, accountID, hasPermissions, permissions)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string, bool, []model.Permission) error); ok {
		r0 = rf(context, accountID, hasPermissions, permissions)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateAccountRoles provides a mock function with given fields: context, accountID, hasPermissions, roles
func (_m *Storage) UpdateAccountRoles(context storage.TransactionContext, accountID string, hasPermissions bool, roles []model.AccountRole) error {
	ret := _m.Called(context, accountID, hasPermissions, roles)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, string, bool, []model.AccountRole) error); ok {
		r0 = rf(context, accountID, hasPermissions, roles)
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

// UpdateCredentialValue provides a mock function with given fields: ID, value
func (_m *Storage) UpdateCredentialValue(ID string, value map[string]interface{}) error {
	ret := _m.Called(ID, value)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, map[string]interface{}) error); ok {
		r0 = rf(ID, value)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateLoginSession provides a mock function with given fields: context, loginSession
func (_m *Storage) UpdateLoginSession(context storage.TransactionContext, loginSession model.LoginSession) error {
	ret := _m.Called(context, loginSession)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, model.LoginSession) error); ok {
		r0 = rf(context, loginSession)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateLoginSessionExternalIDs provides a mock function with given fields: accountID, externalIDs
func (_m *Storage) UpdateLoginSessionExternalIDs(accountID string, externalIDs map[string]string) error {
	ret := _m.Called(accountID, externalIDs)

	var r0 error
	if rf, ok := ret.Get(0).(func(string, map[string]string) error); ok {
		r0 = rf(accountID, externalIDs)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

// UpdateMFAType provides a mock function with given fields: context, mfa, accountID
func (_m *Storage) UpdateMFAType(context storage.TransactionContext, mfa *model.MFAType, accountID string) error {
	ret := _m.Called(context, mfa, accountID)

	var r0 error
	if rf, ok := ret.Get(0).(func(storage.TransactionContext, *model.MFAType, string) error); ok {
		r0 = rf(context, mfa, accountID)
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

// UpdateServiceAccount provides a mock function with given fields: account
func (_m *Storage) UpdateServiceAccount(account *model.ServiceAccount) (*model.ServiceAccount, error) {
	ret := _m.Called(account)

	var r0 *model.ServiceAccount
	if rf, ok := ret.Get(0).(func(*model.ServiceAccount) *model.ServiceAccount); ok {
		r0 = rf(account)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*model.ServiceAccount)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.ServiceAccount) error); ok {
		r1 = rf(account)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// UpdateServiceReg provides a mock function with given fields: reg
func (_m *Storage) UpdateServiceReg(reg *model.ServiceReg) error {
	ret := _m.Called(reg)

	var r0 error
	if rf, ok := ret.Get(0).(func(*model.ServiceReg) error); ok {
		r0 = rf(reg)
	} else {
		r0 = ret.Error(0)
	}

	return r0
}

type mockConstructorTestingTNewStorage interface {
	mock.TestingT
	Cleanup(func())
}

// NewStorage creates a new instance of Storage. It also registers a testing interface on the mock and a cleanup function to assert the mocks expectations.
func NewStorage(t mockConstructorTestingTNewStorage) *Storage {
	mock := &Storage{}
	mock.Mock.Test(t)

	t.Cleanup(func() { mock.AssertExpectations(t) })

	return mock
}
