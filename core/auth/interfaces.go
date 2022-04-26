package auth

import (
	"core-building-block/core/model"
	"core-building-block/driven/storage"
	"time"

	"github.com/rokwire/core-auth-library-go/authorization"
	"github.com/rokwire/core-auth-library-go/sigauth"
	"github.com/rokwire/core-auth-library-go/tokenauth"
	"github.com/rokwire/logging-library-go/logs"
)

//authType is the interface for authentication for auth types which are not external for the system(the users do not come from external system)
type authType interface {
	//signUp applies sign up operation
	// Returns:
	//	message (string): Success message if verification is required. If verification is not required, return ""
	//	credentialValue (map): Credential value
	signUp(authType model.AuthType, appOrg model.ApplicationOrganization, creds string, params string, newCredentialID string, l *logs.Log) (string, map[string]interface{}, error)

	//signUpAdmin signs up a new admin user
	// Returns:
	//	password (string): newly generated password
	//	credentialValue (map): Credential value
	signUpAdmin(authType model.AuthType, appOrg model.ApplicationOrganization, identifier string, newCredentialID string) (string, map[string]interface{}, error)

	//verifies credential (checks the verification code generated on email signup for email auth type)
	// Returns:
	//	authTypeCreds (map[string]interface{}): Updated Credential.Value
	verifyCredential(credential *model.Credential, verification string, l *logs.Log) (map[string]interface{}, error)

	//sends the verification code to the identifier
	sendVerifyCredential(credential *model.Credential, appName string, l *logs.Log) error

	//restarts the credential verification
	restartCredentialVerification(credential *model.Credential, appName string, l *logs.Log) error

	//updates the value of the credential object with new value
	// Returns:
	//	authTypeCreds (map[string]interface{}): Updated Credential.Value
	resetCredential(credential *model.Credential, resetCode *string, params string, l *logs.Log) (map[string]interface{}, error)

	//apply forgot credential for the auth type (generates a reset password link with code and expiry and sends it to given identifier for email auth type)
	forgotCredential(credential *model.Credential, identifier string, appName string, l *logs.Log) (map[string]interface{}, error)

	//getUserIdentifier parses the credentials and returns the user identifier
	// Returns:
	//	userIdentifier (string): User identifier
	getUserIdentifier(creds string) (string, error)

	//isCredentialVerified says if the credential is verified
	// Returns:
	//	verified (bool): is credential verified
	//	expired (bool): is credential verification expired
	isCredentialVerified(credential *model.Credential, l *logs.Log) (*bool, *bool, error)

	//checkCredentials checks if the account credentials are valid for the account auth type
	checkCredentials(accountAuthType model.AccountAuthType, creds string, l *logs.Log) (string, error)
}

//externalAuthType is the interface for authentication for auth types which are external for the system(the users comes from external system).
//these are the different identity providers - illinois_oidc etc
type externalAuthType interface {
	//getLoginUrl retrieves and pre-formats a login url and params for the SSO provider
	getLoginURL(authType model.AuthType, appType model.ApplicationType, redirectURI string, l *logs.Log) (string, map[string]interface{}, error)
	//externalLogin logins in the external system and provides the authenticated user
	externalLogin(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, error)
	//refresh refreshes tokens
	refresh(params map[string]interface{}, authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, error)
}

//anonymousAuthType is the interface for authentication for auth types which are anonymous
type anonymousAuthType interface {
	//checkCredentials checks the credentials for the provided app and organization
	//	Returns anonymous profile identifier
	checkCredentials(creds string) (string, map[string]interface{}, error)
}

//serviceAuthType is the interface for authentication for non-human clients
type serviceAuthType interface {
	checkCredentials(r *sigauth.Request, creds interface{}, params map[string]interface{}) ([]model.ServiceAccount, error)
	addCredentials(creds *model.ServiceAccountCredential) (map[string]interface{}, error)
}

//mfaType is the interface for multi-factor authentication
type mfaType interface {
	//verify verifies the code based on stored mfa params
	verify(context storage.TransactionContext, mfa *model.MFAType, accountID string, code string) (*string, error)
	//enroll creates a mfa type to be added to an account
	enroll(identifier string) (*model.MFAType, error)
	//sendCode generates a mfa code and expiration time and sends the code to the user
	sendCode(identifier string) (string, *time.Time, error)
}

//APIs is the interface which defines the APIs provided by the auth package
type APIs interface {
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
	Login(ipAddress string, deviceType string, deviceOS *string, deviceID string,
		authenticationType string, creds string, apiKey string, appTypeIdentifier string, orgID string, params string,
		profile model.Profile, preferences map[string]interface{}, admin bool, l *logs.Log) (*string, *model.LoginSession, []model.MFAType, error)

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
	//		l (*logs.Log): Log object pointer for request
	//	Returns:
	//		Login session (*LoginSession): Signed ROKWIRE access token to be used to authorize future requests
	//			Access token (string): Signed ROKWIRE access token to be used to authorize future requests
	//			Refresh Token (string): Refresh token that can be sent to refresh the access token once it expires
	//			Params (interface{}): authType-specific set of parameters passed back to client
	Refresh(refreshToken string, apiKey string, l *logs.Log) (*model.LoginSession, error)

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
	CreateAdminAccount(authenticationType string, appTypeIdentifier string, orgID string, identifier string, permissions []string,
		roles []string, groups []string, profile model.Profile, creatorAppID *string, l *logs.Log) (*model.Account, string, error)

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
	GetServiceAccountParams(accountID string, r *sigauth.Request, l *logs.Log) ([]model.AppOrgPair, error)

	//GetServiceAccessToken returns an access token for a non-human client
	GetServiceAccessToken(r *sigauth.Request, l *logs.Log) (string, error)

	//GetServiceAccounts gets all service accounts matching a search
	GetServiceAccounts(params map[string]interface{}) ([]model.ServiceAccount, error)

	//RegisterServiceAccount registers a service account
	RegisterServiceAccount(accountID *string, fromAppID *string, fromOrgID *string, name *string, appID *string, orgID *string,
		permissions *[]string, firstParty *bool, creds []model.ServiceAccountCredential, l *logs.Log) (*model.ServiceAccount, error)

	//DeregisterServiceAccount deregisters a service account
	DeregisterServiceAccount(accountID string) error

	//GetServiceAccountInstance gets a service account instance
	GetServiceAccountInstance(accountID string, appID *string, orgID *string) (*model.ServiceAccount, error)

	//UpdateServiceAccountInstance updates a service account instance
	UpdateServiceAccountInstance(id string, appID *string, orgID *string, name string, permissions []string) (*model.ServiceAccount, error)

	//DeregisterServiceAccountInstance deregisters a service account instance
	DeregisterServiceAccountInstance(id string, appID *string, orgID *string) error

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
	AuthorizeService(claims tokenauth.Claims, serviceID string, approvedScopes []authorization.Scope, l *logs.Log) (string, []authorization.Scope, *model.ServiceReg, error)

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
	InitializeSystemAccount(context storage.TransactionContext, authType model.AuthType, appOrg model.ApplicationOrganization, allSystemPermissionID string, email string, password string, l *logs.Log) (string, error)

	//DeleteAccount deletes an account for the given id
	DeleteAccount(id string) error

	//GetAdminToken returns an admin token for the specified application
	GetAdminToken(claims tokenauth.Claims, appID string, l *logs.Log) (string, error)

	//GetAuthKeySet generates a JSON Web Key Set for auth service registration
	GetAuthKeySet() (*model.JSONWebKeySet, error)

	//GetServiceRegistrations retrieves all service registrations
	GetServiceRegistrations(serviceIDs []string) ([]model.ServiceReg, error)

	//RegisterService creates a new service registration
	RegisterService(reg *model.ServiceReg) error

	//UpdateServiceRegistration updates an existing service registration
	UpdateServiceRegistration(reg *model.ServiceReg) error

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

//Storage interface to communicate with the storage
type Storage interface {
	RegisterStorageListener(storageListener storage.Listener)

	PerformTransaction(func(context storage.TransactionContext) error) error

	//AuthTypes
	FindAuthType(codeOrID string) (*model.AuthType, error)

	//LoginsSessions
	InsertLoginSession(context storage.TransactionContext, session model.LoginSession) error
	FindLoginSessions(context storage.TransactionContext, identifier string) ([]model.LoginSession, error)
	FindLoginSession(refreshToken string) (*model.LoginSession, error)
	FindAndUpdateLoginSession(context storage.TransactionContext, id string) (*model.LoginSession, error)
	UpdateLoginSession(context storage.TransactionContext, loginSession model.LoginSession) error
	DeleteLoginSession(context storage.TransactionContext, id string) error
	DeleteLoginSessionsByIDs(context storage.TransactionContext, ids []string) error
	DeleteLoginSessionsByAccountAuthTypeID(context storage.TransactionContext, id string) error
	DeleteLoginSessionsByIdentifier(context storage.TransactionContext, identifier string) error

	//LoginsSessions - predefined queries for manage deletion logic
	DeleteMFAExpiredSessions() error
	FindSessionsLazy(appID string, orgID string) ([]model.LoginSession, error)
	///

	//Accounts
	FindAccount(appOrgID string, authTypeID string, accountAuthTypeIdentifier string) (*model.Account, error)
	FindAccountByID(context storage.TransactionContext, id string) (*model.Account, error)
	InsertAccount(context storage.TransactionContext, account model.Account) (*model.Account, error)
	SaveAccount(context storage.TransactionContext, account *model.Account) error
	DeleteAccount(context storage.TransactionContext, id string) error

	//Profiles
	UpdateProfile(context storage.TransactionContext, profile model.Profile) error
	FindProfiles(appID string, authTypeID string, accountAuthTypeIdentifier string) ([]model.Profile, error)

	//ServiceAccounts
	FindServiceAccount(context storage.TransactionContext, accountID string, appID *string, orgID *string) (*model.ServiceAccount, error)
	FindServiceAccounts(params map[string]interface{}) ([]model.ServiceAccount, error)
	InsertServiceAccount(account *model.ServiceAccount) error
	UpdateServiceAccount(account *model.ServiceAccount) (*model.ServiceAccount, error)
	DeleteServiceAccount(accountID string, appID *string, orgID *string) error
	DeleteServiceAccounts(accountID string) error

	//ServiceAccountCredentials
	InsertServiceAccountCredential(accountID string, creds *model.ServiceAccountCredential) error
	DeleteServiceAccountCredential(accountID string, credID string) error

	//AccountAuthTypes
	FindAccountByAuthTypeID(context storage.TransactionContext, id string) (*model.Account, error)
	InsertAccountAuthType(item model.AccountAuthType) error
	UpdateAccountAuthType(item model.AccountAuthType) error
	DeleteAccountAuthType(context storage.TransactionContext, item model.AccountAuthType) error

	//ExternalIDs
	UpdateAccountExternalIDs(accountID string, externalIDs map[string]string) error
	UpdateLoginSessionExternalIDs(accountID string, externalIDs map[string]string) error

	//Applications
	FindApplication(ID string) (*model.Application, error)

	//Organizations
	FindOrganization(id string) (*model.Organization, error)

	//Credentials
	InsertCredential(context storage.TransactionContext, creds *model.Credential) error
	FindCredential(context storage.TransactionContext, ID string) (*model.Credential, error)
	UpdateCredential(context storage.TransactionContext, creds *model.Credential) error
	UpdateCredentialValue(ID string, value map[string]interface{}) error
	DeleteCredential(context storage.TransactionContext, ID string) error

	//MFA
	FindMFAType(context storage.TransactionContext, accountID string, identifier string, mfaType string) (*model.MFAType, error)
	FindMFATypes(accountID string) ([]model.MFAType, error)
	InsertMFAType(context storage.TransactionContext, mfa *model.MFAType, accountID string) error
	UpdateMFAType(context storage.TransactionContext, mfa *model.MFAType, accountID string) error
	DeleteMFAType(context storage.TransactionContext, accountID string, identifier string, mfaType string) error

	//ServiceRegs
	FindServiceRegs(serviceIDs []string) ([]model.ServiceReg, error)
	FindServiceReg(serviceID string) (*model.ServiceReg, error)
	InsertServiceReg(reg *model.ServiceReg) error
	UpdateServiceReg(reg *model.ServiceReg) error
	SaveServiceReg(reg *model.ServiceReg) error
	DeleteServiceReg(serviceID string) error

	//IdentityProviders
	LoadIdentityProviders() ([]model.IdentityProvider, error)

	//ServiceAuthorizations
	FindServiceAuthorization(userID string, orgID string) (*model.ServiceAuthorization, error)
	SaveServiceAuthorization(authorization *model.ServiceAuthorization) error
	DeleteServiceAuthorization(userID string, orgID string) error

	//APIKeys
	LoadAPIKeys() ([]model.APIKey, error)
	InsertAPIKey(context storage.TransactionContext, apiKey model.APIKey) (*model.APIKey, error)
	UpdateAPIKey(apiKey model.APIKey) error
	DeleteAPIKey(ID string) error

	//ApplicationTypes
	FindApplicationType(id string) (*model.ApplicationType, error)

	//ApplicationsOrganizations
	FindApplicationsOrganizations() ([]model.ApplicationOrganization, error)
	FindApplicationOrganization(appID string, orgID string) (*model.ApplicationOrganization, error)

	//Permissions
	FindPermissionsByName(names []string) ([]model.Permission, error)

	//Device
	FindDevice(context storage.TransactionContext, deviceID string, accountID string) (*model.Device, error)
	InsertDevice(context storage.TransactionContext, device model.Device) (*model.Device, error)
	DeleteDevice(context storage.TransactionContext, id string) error

	//Permissions
	FindPermissions(context storage.TransactionContext, ids []string) ([]model.Permission, error)

	//ApplicationRoles
	FindAppOrgRolesByIDs(context storage.TransactionContext, ids []string, appOrgID string) ([]model.AppOrgRole, error)
	//AccountRoles
	UpdateAccountRoles(accountID string, roles []model.AccountRole) error

	//ApplicationGroups
	FindAppOrgGroupsByIDs(context storage.TransactionContext, ids []string, appOrgID string) ([]model.AppOrgGroup, error)
	//AccountGroups
	UpdateAccountGroups(accountID string, groups []model.AccountGroup) error
}

//ProfileBuildingBlock is used by auth to communicate with the profile building block.
type ProfileBuildingBlock interface {
	GetProfileBBData(queryParams map[string]string, l *logs.Log) (*model.Profile, map[string]interface{}, error)
}

//Emailer is used by core to send emails
type Emailer interface {
	Send(toEmail string, subject string, body string, attachmentFilename *string) error
}
