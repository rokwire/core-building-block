// Code generated by mockery v0.0.0-dev. DO NOT EDIT.

package mocks

import (
	logs "github.com/rokwire/logging-library-go/logs"
	mock "github.com/stretchr/testify/mock"

	model "core-building-block/core/model"
)

// authType is an autogenerated mock type for the authType type
type authType struct {
	mock.Mock
}

// checkCredentials provides a mock function with given fields: accountAuthType, creds, l
func (_m *authType) checkCredentials(accountAuthType model.AccountAuthType, creds string, l *logs.Log) (string, error) {
	ret := _m.Called(accountAuthType, creds, l)

	var r0 string
	if rf, ok := ret.Get(0).(func(model.AccountAuthType, string, *logs.Log) string); ok {
		r0 = rf(accountAuthType, creds, l)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(model.AccountAuthType, string, *logs.Log) error); ok {
		r1 = rf(accountAuthType, creds, l)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// getUserIdentifier provides a mock function with given fields: creds
func (_m *authType) getUserIdentifier(creds string) (string, error) {
	ret := _m.Called(creds)

	var r0 string
	if rf, ok := ret.Get(0).(func(string) string); ok {
		r0 = rf(creds)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(string) error); ok {
		r1 = rf(creds)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// signUp provides a mock function with given fields: authType, appType, appOrg, creds, params, newCredentialID, l
func (_m *authType) signUp(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, newCredentialID string, l *logs.Log) (string, map[string]interface{}, error) {
	ret := _m.Called(authType, appType, appOrg, creds, params, newCredentialID, l)

	var r0 string
	if rf, ok := ret.Get(0).(func(model.AuthType, model.ApplicationType, model.ApplicationOrganization, string, string, string, *logs.Log) string); ok {
		r0 = rf(authType, appType, appOrg, creds, params, newCredentialID, l)
	} else {
		r0 = ret.Get(0).(string)
	}

	var r1 map[string]interface{}
	if rf, ok := ret.Get(1).(func(model.AuthType, model.ApplicationType, model.ApplicationOrganization, string, string, string, *logs.Log) map[string]interface{}); ok {
		r1 = rf(authType, appType, appOrg, creds, params, newCredentialID, l)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(map[string]interface{})
		}
	}

	var r2 error
	if rf, ok := ret.Get(2).(func(model.AuthType, model.ApplicationType, model.ApplicationOrganization, string, string, string, *logs.Log) error); ok {
		r2 = rf(authType, appType, appOrg, creds, params, newCredentialID, l)
	} else {
		r2 = ret.Error(2)
	}

	return r0, r1, r2
}

// verify provides a mock function with given fields: credential, verification, l
func (_m *authType) verify(credential *model.Credential, verification string, l *logs.Log) (map[string]interface{}, error) {
	ret := _m.Called(credential, verification, l)

	var r0 map[string]interface{}
	if rf, ok := ret.Get(0).(func(*model.Credential, string, *logs.Log) map[string]interface{}); ok {
		r0 = rf(credential, verification, l)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(map[string]interface{})
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(*model.Credential, string, *logs.Log) error); ok {
		r1 = rf(credential, verification, l)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}
