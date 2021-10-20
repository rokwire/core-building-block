package auth

import (
	"core-building-block/core/model"
	"core-building-block/driven/storage"
	"time"

	"github.com/rokwire/core-auth-library-go/authorization"
	"github.com/rokwire/core-auth-library-go/tokenauth"
	"github.com/rokwire/logging-library-go/logs"
	"go.mongodb.org/mongo-driver/mongo"
)

//authType is the interface for authentication for auth types which are not external for the system(the users do not come from external system)
type authType interface {
	//signUp applies sign up operation
	// Returns:
	//	message (string): Success message if verification is required. If verification is not required, return ""
	//	identifier (*string): The unique identifier
	//	credentialValue (map): Credential value
	signUp(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, newCredentialID string, l *logs.Log) (string, *string, map[string]interface{}, error)

	//checks the verification code generated on email signup
	// Returns:
	//	authTypeCreds (map[string]interface{}): Updated Credential.Value
	verify(credential *model.Credential, verification string, l *logs.Log) (map[string]interface{}, error)

	//userExist checks if the user exists for application and organizations
	// Returns:
	//	accountAuthType (*model.AccountAuthType): User account auth type
	userExist(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, l *logs.Log) (*model.AccountAuthType, error)

	//checkCredentials checks if the account credentials are valid for the account auth type
	checkCredentials(accountAuthType model.AccountAuthType, creds string, l *logs.Log) (string, *bool, error)
}

//externalAuthType is the interface for authentication for auth types which are external for the system(the users comes from external system).
//these are the different identity providers - illinois_oidc etc
type externalAuthType interface {
	//getLoginUrl retrieves and pre-formats a login url and params for the SSO provider
	getLoginURL(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, redirectURI string, l *logs.Log) (string, map[string]interface{}, error)
	//externalLogin logins in the external system and provides the authenticated user
	externalLogin(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, error)
	//userExist checks if the user exists
	userExist(externalUserIdentifier string, authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, l *logs.Log) (*model.Account, error)
	//refresh refreshes tokens
	refresh(params map[string]interface{}, authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, l *logs.Log) (map[string]interface{}, error)
}

//anonymousAuthType is the interface for authentication for auth types which are anonymous
type anonymousAuthType interface {
	//checkCredentials checks the credentials for the provided app and organization
	//	Returns anonymous profile identifier
	checkCredentials(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, l *logs.Log) (string, map[string]interface{}, error)
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
	//		appTypeIdentifier (string): identifier of the app type/client that the user is logging in from
	//		orgID (string): ID of the organization that the user is logging in
	//		params (string): JSON encoded params defined by specified auth type
	//		profile (Profile): Account profile
	//		preferences (map): Account preferences
	//		l (*logs.Log): Log object pointer for request
	//	Returns:
	//		Message (*string): message
	//		Login session (*LoginSession): Signed ROKWIRE access token to be used to authorize future requests
	//			Access token (string): Signed ROKWIRE access token to be used to authorize future requests
	//			Refresh Token (string): Refresh token that can be sent to refresh the access token once it expires
	//			AccountAuthType (AccountAuthType): AccountAuthType object for authenticated user
	//			Params (interface{}): authType-specific set of parameters passed back to client
	Login(ipAddress string, deviceType string, deviceOS *string, deviceID string,
		authenticationType string, creds string, appTypeIdentifier string, orgID string, params string,
		profile model.Profile, preferences map[string]interface{}, l *logs.Log) (*string, *model.LoginSession, error)

	//Refresh refreshes an access token using a refresh token
	//	Input:
	//		refreshToken (string): Refresh token
	//		l (*logs.Log): Log object pointer for request
	//	Returns:
	//		Login session (*LoginSession): Signed ROKWIRE access token to be used to authorize future requests
	//			Access token (string): Signed ROKWIRE access token to be used to authorize future requests
	//			Refresh Token (string): Refresh token that can be sent to refresh the access token once it expires
	//			Params (interface{}): authType-specific set of parameters passed back to client
	Refresh(refreshToken string, l *logs.Log) (*model.LoginSession, error)

	//Verify checks the verification code in the credentials collection
	Verify(id string, verification string, l *logs.Log) error

	//GetLoginURL returns a pre-formatted login url for SSO providers
	//	Input:
	//		authType (string): Name of the authentication method for provided creds (eg. "email", "username", "illinois_oidc")
	//		appTypeIdentifier (string): Identifier of the app type/client that the user is logging in from
	//		orgID (string): ID of the organization that the user is logging in
	//		redirectURI (string): Registered redirect URI where client will receive response
	//		l (*loglib.Log): Log object pointer for request
	//	Returns:
	//		Login URL (string): SSO provider login URL to be launched in a browser
	//		Params (map[string]interface{}): Params to be sent in subsequent request (if necessary)
	GetLoginURL(authType string, appTypeIdentifier string, orgID string, redirectURI string, l *logs.Log) (string, map[string]interface{}, error)

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

	//LinkCreds links new credentials to an existing account.
	//The authentication method must be one of the supported for the application.
	//	Input:
	//		accountID (string): ID of the account to link the creds to
	//		authenticationType (string): Name of the authentication method for provided creds (eg. "email", "username", "illinois_oidc")
	//		creds (string): Credentials/JSON encoded credential structure defined for the specified auth type
	//		params (string): JSON encoded params defined by specified auth type
	//		l (*logs.Log): Log object pointer for request
	//	Returns:
	//		Message (*string): message
	//		Params (interface{}): authType-specific set of parameters passed back to client
	LinkCreds(accountID string, authenticationType string, creds string, params string, l *logs.Log) (*string, interface{}, error)

	//GetScopedAccessToken returns a scoped access token with the requested scopes
	GetScopedAccessToken(claims tokenauth.Claims, serviceID string, scopes []authorization.Scope) (string, error)

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

	//GetAPIKey finds and returns the API key for the provided org and app
	GetAPIKey(orgID string, appID string) (*model.APIKey, error)

	//CreateAPIKey creates a new API key for the provided org and app
	CreateAPIKey(apiKey *model.APIKey) error

	//UpdateAPIKey updates an existing API key
	UpdateAPIKey(apiKey *model.APIKey) error

	//DeleteAPIKey deletes an existing API key
	DeleteAPIKey(orgID string, appID string) error
}

//Storage interface to communicate with the storage
type Storage interface {
	RegisterStorageListener(storageListener storage.Listener)

	//AuthTypes
	LoadAuthTypes() ([]model.AuthType, error)
	FindAuthType(codeOrID string) (*model.AuthType, error)

	//LoginsSessions
	InsertLoginSession(loginSession model.LoginSession) (*model.LoginSession, error)
	FindLoginSession(refreshToken string) (*model.LoginSession, error)
	UpdateLoginSession(loginSession model.LoginSession) error
	DeleteLoginSession(id string) error

	//Accounts
	FindAccount(appID string, orgID string, authTypeID string, accountAuthTypeIdentifier string) (*model.Account, error)
	InsertAccount(account model.Account) (*model.Account, error)
	UpdateAccount(account *model.Account, orgID string, newOrgData *map[string]interface{}) (*model.Account, error)
	DeleteAccount(id string) error

	//AccountAuthTypes
	UpdateAccountAuthType(item model.AccountAuthType) error

	//Organizations
	FindOrganization(id string) (*model.Organization, error)

	//Credentials
	// FindCredentialsByID(ID string) (*model.AuthCreds, error)
	// FindCredentials(orgID string, appID string, authType string, params map[string]interface{}) (*model.AuthCreds, error)
	// UpdateCredentials(orgID string, appID string, authType string, creds *model.AuthCreds) error
	// InsertCredentials(creds *model.AuthCreds, context mongo.SessionContext) error
	FindCredential(ID string) (*model.Credential, error)
	UpdateCredential(creds *model.Credential) error
	InsertCredential(creds *model.Credential, context mongo.SessionContext) error

	//RefreshTokens
	FindRefreshToken(token string) (*model.AuthRefresh, error)
	LoadRefreshTokens(orgID string, appID string, credsID string) ([]model.AuthRefresh, error)
	InsertRefreshToken(refresh *model.AuthRefresh) error
	UpdateRefreshToken(token string, refresh *model.AuthRefresh) error
	DeleteRefreshToken(token string) error
	DeleteExpiredRefreshTokens(now *time.Time) error

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
	FindAPIKey(orgID string, appID string) (*model.APIKey, error)
	FindAPIKeys(orgID string) ([]model.APIKey, error)
	InsertAPIKey(apiKey *model.APIKey) error
	UpdateAPIKey(apiKey *model.APIKey) error
	DeleteAPIKey(orgID string, appID string) error

	//ApplicationTypes
	FindApplicationTypeByIdentifier(identifier string) (*model.ApplicationType, error)

	//ApplicationsOrganizations
	LoadApplicationsOrganizations() ([]model.ApplicationOrganization, error)
	FindApplicationOrganizations(appID string, orgID string) (*model.ApplicationOrganization, error)
}

//ProfileBuildingBlock is used by auth to communicate with the profile building block.
type ProfileBuildingBlock interface {
	GetProfileBBData(queryParams map[string]string, l *logs.Log) (*model.Profile, map[string]interface{}, error)
}

//Emailer is used by core to send emails
type Emailer interface {
	Send(toEmail string, subject string, body string, attachmentFilename *string) error
}
