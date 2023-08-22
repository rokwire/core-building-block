// Copyright 2022 Board of Trustees of the University of Illinois.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package interfaces

import (
	"core-building-block/core/model"

	"github.com/rokwire/logging-library-go/v2/logs"
)

// Storage interface to communicate with the storage
type Storage interface {
	RegisterStorageListener(listener StorageListener)

	PerformTransaction(func(adapter Storage) error) error

	//Configs
	FindConfig(configType string, appID string, orgID string) (*model.Config, error)
	FindConfigByID(id string) (*model.Config, error)
	FindConfigs(configType *string) ([]model.Config, error)
	InsertConfig(config model.Config) error
	UpdateConfig(config model.Config) error
	DeleteConfig(id string) error

	//AuthTypes
	FindAuthType(codeOrID string) (*model.AuthType, error)

	//LoginsSessions
	InsertLoginSession(session model.LoginSession) error
	FindLoginSessions(identifier string) ([]model.LoginSession, error)
	FindLoginSessionsByParams(appID string, orgID string, sessionID *string, identifier *string, accountAuthTypeIdentifier *string,
		appTypeID *string, appTypeIdentifier *string, anonymous *bool, deviceID *string, ipAddress *string) ([]model.LoginSession, error)
	FindLoginSession(refreshToken string) (*model.LoginSession, error)
	FindAndUpdateLoginSession(id string) (*model.LoginSession, error)
	UpdateLoginSession(loginSession model.LoginSession) error
	DeleteLoginSession(id string) error
	DeleteLoginSessionsByIDs(ids []string) error
	DeleteLoginSessionsByAccountAuthTypeID(id string) error
	DeleteLoginSessionsByIdentifier(identifier string) error

	//LoginsSessions - predefined queries for manage deletion logic
	DeleteMFAExpiredSessions() error
	FindSessionsLazy(appID string, orgID string) ([]model.LoginSession, error)
	///

	//Accounts
	FindAccount(appOrgID string, authTypeID string, accountAuthTypeIdentifier string) (*model.Account, error)
	FindAccountByID(id string) (*model.Account, error)
	FindAccounts(limit *int, offset *int, appID string, orgID string, accountID *string, firstName *string, lastName *string, authType *string,
		authTypeIdentifier *string, anonymous *bool, hasPermissions *bool, permissions []string, roleIDs []string, groupIDs []string) ([]model.Account, error)
	FindPublicAccounts(appID string, orgID string, limit *int, offset *int, search *string, firstName *string, lastName *string, username *string,
		followingID *string, followerID *string, userID string) ([]model.PublicAccount, error)
	FindAccountsByParams(searchParams map[string]interface{}, appID string, orgID string, limit int, offset int, allAccess bool, approvedKeys []string) ([]map[string]interface{}, error)
	FindAccountsByAccountID(appID string, orgID string, accountIDs []string) ([]model.Account, error)
	InsertAccount(account model.Account) (*model.Account, error)
	SaveAccount(account *model.Account) error
	DeleteAccount(id string) error
	UpdateAccountUsageInfo(accountID string, updateLoginTime bool, updateAccessTokenTime bool, clientVersion *string) error
	UpdateAccountVerified(accountID string, appID string, orgID string, verified bool) error
	CountAccountsByParams(searchParams map[string]interface{}, appID string, orgID string) (int64, error)
	CountAccountsByRoleID(roleID string) (*int64, error)
	CountAccountsByGroupID(groupID string) (*int64, error)

	//Follows
	InsertFollow(follow model.Follow) error
	DeleteFollow(appID string, orgID string, followingID string, followerID string) error

	//Profiles
	UpdateAccountProfile(profile model.Profile) error
	FindAccountProfiles(appID string, authTypeID string, accountAuthTypeIdentifier string) ([]model.Profile, error)

	//Privacy
	UpdateAccountPrivacy(accountID string, privacy model.Privacy) error

	//Preferences
	UpdateAccountPreferences(accountID string, preferences map[string]interface{}) error

	//SystemConfigs
	UpdateAccountSystemConfigs(accountID string, configs map[string]interface{}) error

	//Username
	FindAccountsByUsername(appOrg *model.ApplicationOrganization, username string) ([]model.Account, error)
	UpdateAccountUsername(accountID, username string) error

	//ServiceAccounts
	FindServiceAccount(accountID string, appID string, orgID string) (*model.ServiceAccount, error)
	FindServiceAccounts(params map[string]interface{}) ([]model.ServiceAccount, error)
	InsertServiceAccount(account *model.ServiceAccount) error
	UpdateServiceAccount(account *model.ServiceAccount) (*model.ServiceAccount, error)
	DeleteServiceAccount(accountID string, appID string, orgID string) error
	DeleteServiceAccounts(accountID string) error

	//ServiceAccountCredentials
	InsertServiceAccountCredential(accountID string, creds *model.ServiceAccountCredential) error
	DeleteServiceAccountCredential(accountID string, credID string) error

	//AccountAuthTypes
	FindAccountByAuthTypeID(id string) (*model.Account, error)
	InsertAccountAuthType(item model.AccountAuthType) error
	DeleteAccountAuthType(item model.AccountAuthType) error

	//ExternalIDs
	UpdateAccountExternalIDs(accountID string, externalIDs map[string]string) error
	UpdateLoginSessionExternalIDs(accountID string, externalIDs map[string]string) error

	//Applications
	InsertApplication(application model.Application) (*model.Application, error)
	SaveApplication(application model.Application) error
	FindApplication(ID string) (*model.Application, error)
	FindApplications() ([]model.Application, error)

	//Organizations
	InsertOrganization(organization model.Organization) (*model.Organization, error)
	UpdateOrganization(ID string, name string, requestType string, organizationDomains []string) error
	FindOrganization(id string) (*model.Organization, error)
	FindSystemOrganization() (*model.Organization, error)
	FindOrganizations() ([]model.Organization, error)

	//Credentials
	InsertCredential(creds *model.Credential) error
	FindCredential(ID string) (*model.Credential, error)
	UpdateCredential(creds *model.Credential) error
	UpdateCredentialValue(ID string, value map[string]interface{}) error
	DeleteCredential(ID string) error

	//MFA
	FindMFAType(accountID string, identifier string, mfaType string) (*model.MFAType, error)
	FindMFATypes(accountID string) ([]model.MFAType, error)
	InsertMFAType(mfa *model.MFAType, accountID string) error
	UpdateMFAType(mfa *model.MFAType, accountID string) error
	DeleteMFAType(accountID string, identifier string, mfaType string) error

	//ServiceRegs
	MigrateServiceRegs() error
	FindServiceRegs(serviceIDs []string) []model.ServiceRegistration
	FindServiceReg(serviceID string) (*model.ServiceRegistration, error)
	InsertServiceReg(reg *model.ServiceRegistration) error
	UpdateServiceReg(reg *model.ServiceRegistration) error
	SaveServiceReg(reg *model.ServiceRegistration, immediateCache bool) error
	DeleteServiceReg(serviceID string) error

	//AuthTypes
	FindAuthTypes() ([]model.AuthType, error)
	InsertAuthType(authType model.AuthType) (*model.AuthType, error)
	UpdateAuthTypes(ID string, code string, description string, isExternal bool, isAnonymous bool, useCredentials bool, ignoreMFA bool, params map[string]interface{}) error

	//IdentityProviders
	LoadIdentityProviders() ([]model.IdentityProvider, error)

	//ServiceAuthorizations
	FindServiceAuthorization(userID string, orgID string) (*model.ServiceAuthorization, error)
	SaveServiceAuthorization(authorization *model.ServiceAuthorization) error
	DeleteServiceAuthorization(userID string, orgID string) error

	//APIKeys
	LoadAPIKeys() ([]model.APIKey, error)
	InsertAPIKey(apiKey model.APIKey) (*model.APIKey, error)
	UpdateAPIKey(apiKey model.APIKey) error
	DeleteAPIKey(ID string) error

	//ApplicationTypes
	FindApplicationType(id string) (*model.ApplicationType, error)

	//ApplicationsOrganizations
	FindApplicationsOrganizations() ([]model.ApplicationOrganization, error)
	FindApplicationsOrganizationsByOrgID(orgID string) ([]model.ApplicationOrganization, error)
	FindApplicationOrganizations(appID *string, orgID *string) ([]model.ApplicationOrganization, error)
	FindApplicationOrganization(appID string, orgID string) (*model.ApplicationOrganization, error)
	FindApplicationOrganizationByID(ID string) (*model.ApplicationOrganization, error)
	InsertApplicationOrganization(applicationOrganization model.ApplicationOrganization) (*model.ApplicationOrganization, error)
	UpdateApplicationOrganization(applicationOrganization model.ApplicationOrganization) error

	//Device
	FindDevice(deviceID string, accountID string) (*model.Device, error)
	InsertDevice(device model.Device) (*model.Device, error)
	SaveDevice(device *model.Device) error
	DeleteDevice(id string) error

	//Permissions
	FindPermissions(ids []string) ([]model.Permission, error)
	FindPermissionsByName(names []string) ([]model.Permission, error)
	FindPermissionsByServiceIDs(serviceIDs []string) ([]model.Permission, error)
	InsertPermission(item model.Permission) error
	InsertPermissions(items []model.Permission) error
	UpdatePermission(item model.Permission) error
	DeletePermission(id string) error
	//AccountPermissions
	InsertAccountPermissions(accountID string, permissions []model.Permission) error
	UpdateAccountPermissions(accountID string, permissions []model.Permission) error
	DeleteAccountPermissions(accountID string, permissionNames []string) error

	//ApplicationRoles
	FindAppOrgRoles(appOrgID string) ([]model.AppOrgRole, error)
	FindAppOrgRolesByIDs(ids []string, appOrgID string) ([]model.AppOrgRole, error)
	FindAppOrgRole(id string, appOrgID string) (*model.AppOrgRole, error)
	InsertAppOrgRole(item model.AppOrgRole) error
	UpdateAppOrgRole(item model.AppOrgRole) error
	DeleteAppOrgRole(id string) error
	InsertAppOrgRolePermissions(roleID string, permissionNames []model.Permission) error
	//AccountRoles
	UpdateAccountRoles(accountID string, roles []model.AccountRole) error
	InsertAccountRoles(accountID string, appOrgID string, roles []model.AccountRole) error
	DeleteAccountRoles(accountID string, roleIDs []string) error

	//ApplicationGroups
	FindAppOrgGroups(appOrgID string) ([]model.AppOrgGroup, error)
	FindAppOrgGroupsByIDs(ids []string, appOrgID string) ([]model.AppOrgGroup, error)
	FindAppOrgGroup(id string, appOrgID string) (*model.AppOrgGroup, error)
	InsertAppOrgGroup(item model.AppOrgGroup) error
	UpdateAppOrgGroup(item model.AppOrgGroup) error
	DeleteAppOrgGroup(id string) error
	CountGroupsByRoleID(roleID string) (*int64, error)
	//AccountGroups
	InsertAccountGroups(accountID string, appOrgID string, groups []model.AccountGroup) error
	InsertAccountsGroup(group model.AccountGroup, accountIDs []string) error
	UpdateAccountGroups(accountID string, groups []model.AccountGroup) error
	RemoveAccountsGroup(groupID string, accountIDs []string) error

	//AccountScopes
	UpdateAccountScopes(accountID string, scopes []string) error

	//AppConfigs
	FindAppConfigs(appTypeIdentifier string, appOrgID *string, versionNumbers *model.VersionNumbers) ([]model.ApplicationConfig, error)
	FindAppConfigByVersion(appTypeIdentifier string, appOrgID *string, versionNumbers model.VersionNumbers) (*model.ApplicationConfig, error)
	FindAppConfigByID(ID string) (*model.ApplicationConfig, error)
	InsertAppConfig(item model.ApplicationConfig) (*model.ApplicationConfig, error)
	UpdateAppConfig(ID string, appType model.ApplicationType, appOrg *model.ApplicationOrganization, version model.Version, data map[string]interface{}) error
	DeleteAppConfig(ID string) error
}

// StorageListener represents storage listener
type StorageListener interface {
	OnAPIKeysUpdated()
	OnAuthTypesUpdated()
	OnIdentityProvidersUpdated()
	OnServiceRegistrationsUpdated()
	OnOrganizationsUpdated()
	OnApplicationsUpdated()
	OnApplicationsOrganizationsUpdated()
	OnApplicationConfigsUpdated()
	OnConfigsUpdated()
}

// ProfileBuildingBlock is used by auth to communicate with the profile building block.
type ProfileBuildingBlock interface {
	GetProfileBBData(queryParams map[string]string, l *logs.Log) (*model.Profile, map[string]interface{}, error)
}

// IdentityBuildingBlock is used by auth to communicate with the identity building block.
type IdentityBuildingBlock interface {
	GetUserProfile(baseURL string, externalUser model.ExternalSystemUser, externalAccessToken string, l *logs.Log) (*model.Profile, error)
}

// Emailer is used by core to send emails
type Emailer interface {
	Send(toEmail string, subject string, body string, attachmentFilename *string) error
}
