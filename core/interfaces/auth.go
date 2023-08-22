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

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/rokwire/core-auth-library-go/v3/authorization"
	"github.com/rokwire/core-auth-library-go/v3/sigauth"
	"github.com/rokwire/core-auth-library-go/v3/tokenauth"
	"github.com/rokwire/logging-library-go/v2/logs"
)

// Auth is the interface which defines the APIs provided by the auth package
type Auth interface {
	//Start starts the auth service
	Start()

	//GetHost returns the host/issuer of the auth service
	GetHost() string

	//Login logs a user in a specific application using the specified credentials and authentication method.
	//The authentication method must be one of the supported for the application.
	//	Input:
	//		ipAddress (string): Client's IP address
	//		deviceType (string): "mobile" or "web" or "desktop" etc
	//		deviceOS (*string): Device OS
	//		deviceID (string): Device ID
	//		authenticationType (string): Name of the authentication method for provided creds (eg. "email", "username", "illinois_oidc")
	//		creds (string): Credentials/JSON encoded credential structure defined for the specified auth type
	//		apiKey (string): API key to validate the specified app
	//		appTypeIdentifier (string): identifier of the app type/client that the user is logging in from
	//		orgID (string): ID of the organization that the user is logging in
	//		params (string): JSON encoded params defined by specified auth type
	//      clientVersion(*string): Most recent client version
	//		profile (Profile): Account profile
	//		preferences (map): Account preferences
	//		admin (bool): Is this an admin login?
	//		l (*logs.Log): Log object pointer for request
	//	Returns:
	//		Message (*string): message
	//		Login session (*LoginSession): Signed ROKWIRE access token to be used to authorize future requests
	//			Access token (string): Signed ROKWIRE access token to be used to authorize future requests
	//			Refresh Token (string): Refresh token that can be sent to refresh the access token once it expires
	//			AccountAuthType (AccountAuthType): AccountAuthType object for authenticated user
	//			Params (interface{}): authType-specific set of parameters passed back to client
	//			State (string): login state used if account is enrolled in MFA
	//		MFA types ([]model.MFAType): list of MFA types account is enrolled in
	Login(ipAddress string, deviceType string, deviceOS *string, deviceID string, authenticationType string, creds string, apiKey string,
		appTypeIdentifier string, orgID string, params string, clientVersion *string, profile model.Profile, privacy model.Privacy,
		preferences map[string]interface{}, username string, admin bool, l *logs.Log) (*string, *model.LoginSession, []model.MFAType, error)

	//Logout logouts an account from app/org
	//	Input:
	//		allSessions (bool): If to remove the current session only or all sessions for the app/org for the account
	Logout(appID string, orgID string, currentAccountID string, sessionID string, allSessions bool, l *logs.Log) error

	//AccountExists checks if a user is already registered
	//The authentication method must be one of the supported for the application.
	//	Input:
	//		authenticationType (string): Name of the authentication method for provided creds (eg. "email", "username", "illinois_oidc")
	//		userIdentifier (string): User identifier for the specified auth type
	//		apiKey (string): API key to validate the specified app
	//		appTypeIdentifier (string): identifier of the app type/client that the user is logging in from
	//		orgID (string): ID of the organization that the user is logging in
	//	Returns:
	//		accountExisted (bool): valid when error is nil
	AccountExists(authenticationType string, userIdentifier string, apiKey string, appTypeIdentifier string, orgID string) (bool, error)

	//CanSignIn checks if a user can sign in
	//The authentication method must be one of the supported for the application.
	//	Input:
	//		authenticationType (string): Name of the authentication method for provided creds (eg. "email", "username", "illinois_oidc")
	//		userIdentifier (string): User identifier for the specified auth type
	//		apiKey (string): API key to validate the specified app
	//		appTypeIdentifier (string): identifier of the app type/client being used
	//		orgID (string): ID of the organization being used
	//	Returns:
	//		canSignIn (bool): valid when error is nil
	CanSignIn(authenticationType string, userIdentifier string, apiKey string, appTypeIdentifier string, orgID string) (bool, error)

	//CanLink checks if a user can link a new auth type
	//The authentication method must be one of the supported for the application.
	//	Input:
	//		authenticationType (string): Name of the authentication method for provided creds (eg. "email", "username", "illinois_oidc")
	//		userIdentifier (string): User identifier for the specified auth type
	//		apiKey (string): API key to validate the specified app
	//		appTypeIdentifier (string): identifier of the app type/client being used
	//		orgID (string): ID of the organization being used
	//	Returns:
	//		canLink (bool): valid when error is nil
	CanLink(authenticationType string, userIdentifier string, apiKey string, appTypeIdentifier string, orgID string) (bool, error)

	//Refresh refreshes an access token using a refresh token
	//	Input:
	//		refreshToken (string): Refresh token
	//		apiKey (string): API key to validate the specified app
	//      clientVersion(*string): Most recent client version
	//		l (*logs.Log): Log object pointer for request
	//	Returns:
	//		Login session (*LoginSession): Signed ROKWIRE access token to be used to authorize future requests
	//			Access token (string): Signed ROKWIRE access token to be used to authorize future requests
	//			Refresh Token (string): Refresh token that can be sent to refresh the access token once it expires
	//			Params (interface{}): authType-specific set of parameters passed back to client
	Refresh(refreshToken string, apiKey string, clientVersion *string, l *logs.Log) (*model.LoginSession, error)

	//GetLoginURL returns a pre-formatted login url for SSO providers
	//	Input:
	//		authType (string): Name of the authentication method for provided creds (eg. "email", "username", "illinois_oidc")
	//		appTypeIdentifier (string): Identifier of the app type/client that the user is logging in from
	//		orgID (string): ID of the organization that the user is logging in
	//		redirectURI (string): Registered redirect URI where client will receive response
	//		apiKey (string): API key to validate the specified app
	//		l (*loglib.Log): Log object pointer for request
	//	Returns:
	//		Login URL (string): SSO provider login URL to be launched in a browser
	//		Params (map[string]interface{}): Params to be sent in subsequent request (if necessary)
	GetLoginURL(authType string, appTypeIdentifier string, orgID string, redirectURI string, apiKey string, l *logs.Log) (string, map[string]interface{}, error)

	//LoginMFA verifies a code sent by a user as a final login step for enrolled accounts.
	//The MFA type must be one of the supported for the application.
	//	Input:
	//		apiKey (string): API key to validate the specified app
	//		accountID (string): ID of account user is trying to access
	//		sessionID (string): ID of login session generated during login
	//		identifier (string): Email, phone, or TOTP device name
	//		mfaType (string): Type of MFA code sent
	//		mfaCode (string): Code that must be verified
	//		state (string): Variable used to verify user has already passed credentials check
	//		l (*logs.Log): Log object pointer for request
	//	Returns:
	//		Message (*string): message
	//		Login session (*LoginSession): Signed ROKWIRE access token to be used to authorize future requests
	//			Access token (string): Signed ROKWIRE access token to be used to authorize future requests
	//			Refresh Token (string): Refresh token that can be sent to refresh the access token once it expires
	//			AccountAuthType (AccountAuthType): AccountAuthType object for authenticated user
	LoginMFA(apiKey string, accountID string, sessionID string, identifier string, mfaType string, mfaCode string, state string, l *logs.Log) (*string, *model.LoginSession, error)

	//CreateAdminAccount creates an account for a new admin user
	CreateAdminAccount(authenticationType string, appID string, orgID string, identifier string, profile model.Profile, privacy model.Privacy, username string, permissions []string,
		roleIDs []string, groupIDs []string, scopes []string, creatorPermissions []string, clientVersion *string, l *logs.Log) (*model.Account, map[string]interface{}, error)

	//UpdateAdminAccount updates an existing user's account with new permissions, roles, and groups
	UpdateAdminAccount(authenticationType string, appID string, orgID string, identifier string, permissions []string, roleIDs []string,
		groupIDs []string, scopes []string, updaterPermissions []string, l *logs.Log) (*model.Account, map[string]interface{}, error)

	//CreateAnonymousAccount creates a new anonymous account
	CreateAnonymousAccount(storage Storage, appID string, orgID string, anonymousID string, preferences map[string]interface{},
		systemConfigs map[string]interface{}, skipExistsCheck bool, l *logs.Log) (*model.Account, error)

	//VerifyCredential verifies credential (checks the verification code in the credentials collection)
	VerifyCredential(id string, verification string, l *logs.Log) error

	//SendVerifyCredential sends verification code to identifier
	SendVerifyCredential(authenticationType string, appTypeIdentifier string, orgID string, apiKey string, identifier string, l *logs.Log) error

	//UpdateCredential updates the credential object with the new value
	//	Input:
	//		accountID: id of the associated account to reset
	//		accountAuthTypeID (string): id of the AccountAuthType
	//		params: specific params for the different auth types
	//	Returns:
	//		error: if any
	UpdateCredential(accountID string, accountAuthTypeID string, params string, l *logs.Log) error

	//ForgotCredential initiate forgot credential process (generates a reset link and sends to the given identifier for email auth type)
	//	Input:
	//		authenticationType (string): Name of the authentication method for provided creds (eg. "email", "username", "illinois_oidc")
	//		identifier: identifier of the account auth type
	//		appTypeIdentifier (string): Identifier of the app type/client that the user is logging in from
	//		orgID (string): ID of the organization that the user is logging in
	//		apiKey (string): API key to validate the specified app
	//	Returns:
	//		error: if any
	ForgotCredential(authenticationType string, appTypeIdentifier string, orgID string, apiKey string, identifier string, l *logs.Log) error

	//ResetForgotCredential resets forgot credential
	//	Input:
	//		credsID: id of the credential object
	//		resetCode: code from the reset link
	//		params: specific params for the different auth types
	//	Returns:
	//		error: if any
	ResetForgotCredential(credsID string, resetCode string, params string, l *logs.Log) error

	//VerifyMFA verifies a code sent by a user as a final MFA enrollment step.
	//The MFA type must be one of the supported for the application.
	//	Input:
	//		accountID (string): ID of account for which user is trying to verify MFA
	//		identifier (string): Email, phone, or TOTP device name
	//		mfaType (string): Type of MFA code sent
	//		mfaCode (string): Code that must be verified
	//	Returns:
	//		Message (*string): message
	//		Recovery codes ([]string): List of account recovery codes returned if enrolling in MFA for first time
	VerifyMFA(accountID string, identifier string, mfaType string, mfaCode string) (*string, []string, error)

	//GetMFATypes gets all MFA types set up for an account
	//	Input:
	//		accountID (string): Account ID to find MFA types
	//	Returns:
	//		MFA Types ([]model.MFAType): MFA information for all enrolled types
	GetMFATypes(accountID string) ([]model.MFAType, error)

	//AddMFAType adds a form of MFA to an account
	//	Input:
	//		accountID (string): Account ID to add MFA
	//		identifier (string): Email, phone, or TOTP device name
	//		mfaType (string): Type of MFA to be added
	//	Returns:
	//		MFA Type (*model.MFAType): MFA information for the specified type
	AddMFAType(accountID string, identifier string, mfaType string) (*model.MFAType, error)

	//RemoveMFAType removes a form of MFA from an account
	//	Input:
	//		accountID (string): Account ID to remove MFA
	//		identifier (string): Email, phone, or TOTP device name
	//		mfaType (string): Type of MFA to remove
	RemoveMFAType(accountID string, identifier string, mfaType string) error

	//GetServiceAccountParams returns a list of app, org pairs a service account has access to
	GetServiceAccountParams(accountID string, firstParty bool, r *sigauth.Request, l *logs.Log) ([]model.AppOrgPair, error)

	//GetServiceAccessToken returns an access token for a non-human client
	GetServiceAccessToken(firstParty bool, r *sigauth.Request, l *logs.Log) (string, error)

	//GetAllServiceAccessTokens returns an access token for each app, org pair a service account has access to
	GetAllServiceAccessTokens(firstParty bool, r *sigauth.Request, l *logs.Log) (map[model.AppOrgPair]string, error)

	//GetServiceAccounts gets all service accounts matching a search
	GetServiceAccounts(params map[string]interface{}) ([]model.ServiceAccount, error)

	//RegisterServiceAccount registers a service account
	RegisterServiceAccount(accountID *string, fromAppID *string, fromOrgID *string, name *string, appID string, orgID string, permissions *[]string, scopes []authorization.Scope,
		firstParty *bool, creds []model.ServiceAccountCredential, assignerPermissions []string, l *logs.Log) (*model.ServiceAccount, error)

	//DeregisterServiceAccount deregisters a service account
	DeregisterServiceAccount(accountID string) error

	//GetServiceAccountInstance gets a service account instance
	GetServiceAccountInstance(accountID string, appID string, orgID string) (*model.ServiceAccount, error)

	//UpdateServiceAccountInstance updates a service account instance
	UpdateServiceAccountInstance(id string, appID string, orgID string, name *string, permissions *[]string, scopes []authorization.Scope, assignerPermissions []string) (*model.ServiceAccount, error)

	//DeregisterServiceAccountInstance deregisters a service account instance
	DeregisterServiceAccountInstance(id string, appID string, orgID string) error

	//AddServiceAccountCredential adds a credential to a service account
	AddServiceAccountCredential(accountID string, creds *model.ServiceAccountCredential, l *logs.Log) (*model.ServiceAccountCredential, error)

	//RemoveServiceAccountCredential removes a credential from a service account
	RemoveServiceAccountCredential(accountID string, credID string) error

	//AuthorizeService returns a scoped token for the specified service and the service registration record if authorized or
	//	the service registration record if not. Passing "approvedScopes" will update the service authorization for this user and
	//	return a scoped access token which reflects this change.
	//	Input:
	//		claims (tokenauth.Claims): Claims from un-scoped user access token
	//		serviceID (string): ID of the service to be authorized
	//		approvedScopes ([]string): list of scope strings to be approved
	//		l (*logs.Log): Log object pointer for request
	//	Returns:
	//		Access token (string): Signed scoped access token to be used to authorize requests to the specified service
	//		Approved Scopes ([]authorization.Scope): The approved scopes included in the provided token
	//		Service reg (*model.ServiceReg): The service registration record for the requested service
	AuthorizeService(claims tokenauth.Claims, serviceID string, approvedScopes []authorization.Scope, l *logs.Log) (string, []authorization.Scope, *model.ServiceRegistration, error)

	//LinkAccountAuthType links new credentials to an existing account.
	//The authentication method must be one of the supported for the application.
	//	Input:
	//		accountID (string): ID of the account to link the creds to
	//		authenticationType (string): Name of the authentication method for provided creds (eg. "email", "username", "illinois_oidc")
	//		appTypeIdentifier (string): identifier of the app type/client that the user is logging in from
	//		creds (string): Credentials/JSON encoded credential structure defined for the specified auth type
	//		params (string): JSON encoded params defined by specified auth type
	//		l (*logs.Log): Log object pointer for request
	//	Returns:
	//		message (*string): response message
	//		account (*model.Account): account data after the operation
	LinkAccountAuthType(accountID string, authenticationType string, appTypeIdentifier string, creds string, params string, l *logs.Log) (*string, *model.Account, error)

	//UnlinkAccountAuthType unlinks credentials from an existing account.
	//The authentication method must be one of the supported for the application.
	//	Input:
	//		accountID (string): ID of the account to unlink creds from
	//		authenticationType (string): Name of the authentication method of account auth type to unlink
	//		appTypeIdentifier (string): Identifier of the app type/client that the user is logging in from
	//		identifier (string): Identifier of account auth type to unlink
	//		l (*logs.Log): Log object pointer for request
	//	Returns:
	//		account (*model.Account): account data after the operation
	UnlinkAccountAuthType(accountID string, authenticationType string, appTypeIdentifier string, identifier string, l *logs.Log) (*model.Account, error)

	//InitializeSystemAccount initializes the first system account
	InitializeSystemAccount(storage Storage, authType model.AuthType, appOrg model.ApplicationOrganization, allSystemPermission string, email string, password string, clientVersion string, l *logs.Log) (string, error)

	//GrantAccountPermissions grants new permissions to an account after validating the assigner has required permissions
	GrantAccountPermissions(storage Storage, account *model.Account, permissionNames []string, assignerPermissions []string) error

	//CheckPermissions loads permissions by names from storage and checks that they are assignable and valid for the given appOrgs or revocable
	CheckPermissions(storage Storage, appOrgs []model.ApplicationOrganization, permissionNames []string, assignerPermissions []string, revoke bool) ([]model.Permission, error)

	//GrantAccountRoles grants new roles to an account after validating the assigner has required permissions
	GrantAccountRoles(storage Storage, account *model.Account, roleIDs []string, assignerPermissions []string) error

	//CheckRoles loads appOrg roles by IDs from storage and checks that they are assignable or revocable
	CheckRoles(storage Storage, appOrg *model.ApplicationOrganization, roleIDs []string, assignerPermissions []string, revoke bool) ([]model.AppOrgRole, error)

	//GrantAccountGroups grants new groups to an account after validating the assigner has required permissions
	GrantAccountGroups(storage Storage, account *model.Account, groupIDs []string, assignerPermissions []string) error

	//CheckGroups loads appOrg groups by IDs from storage and checks that they are assignable or revocable
	CheckGroups(storage Storage, appOrg *model.ApplicationOrganization, groupIDs []string, assignerPermissions []string, revoke bool) ([]model.AppOrgGroup, error)

	//DeleteAccount deletes an account for the given id
	DeleteAccount(id string) error

	//GetAdminToken returns an admin token for the specified application and organization
	GetAdminToken(claims tokenauth.Claims, appID string, orgID string, l *logs.Log) (string, error)

	//GetAuthKeySet generates a JSON Web Key Set for auth service registration
	GetAuthKeySet() (jwk.Set, error)

	//GetServiceRegistrations retrieves all service registrations
	GetServiceRegistrations(serviceIDs []string) []model.ServiceRegistration

	//RegisterService creates a new service registration
	RegisterService(reg *model.ServiceRegistration) error

	//UpdateServiceRegistration updates an existing service registration
	UpdateServiceRegistration(reg *model.ServiceRegistration) error

	//DeregisterService deletes an existing service registration
	DeregisterService(serviceID string) error

	//GetApplicationAPIKeys finds and returns the API keys for an application
	GetApplicationAPIKeys(appID string) ([]model.APIKey, error)

	//GetAPIKey finds and returns an API key
	GetAPIKey(ID string) (*model.APIKey, error)

	//CreateAPIKey creates a new API key
	CreateAPIKey(apiKey model.APIKey) (*model.APIKey, error)

	//UpdateAPIKey updates an existing API key
	UpdateAPIKey(apiKey model.APIKey) error

	//DeleteAPIKey deletes an API key
	DeleteAPIKey(ID string) error

	//ValidateAPIKey validates the given API key for the given app ID
	ValidateAPIKey(appID string, apiKey string) error
}
