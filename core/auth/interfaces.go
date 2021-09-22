package auth

import (
	"core-building-block/core/model"
	"core-building-block/driven/storage"
	"time"

	"github.com/rokmetro/auth-library/authorization"
	"github.com/rokmetro/logging-library/logs"
	"go.mongodb.org/mongo-driver/mongo"
)

//authType is the interface for authentication for auth types which are not external for the system(the users do not come from external system)
type authType interface {
	//checks the verification code generated on email signup
	verify(accountAuthType *model.AccountAuthType, id string, verification string, l *logs.Log) error
	//userExist checks if the user exists for application and organizations
	userExist(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, l *logs.Log) (*model.Account, *model.AccountAuthType, error)
	//checkCredentials checks if the account credentials are valid for the account auth type
	checkCredentials(accountAuthType *model.AccountAuthType, creds string, appOrg model.ApplicationOrganization, l *logs.Log) (*string, map[string]interface{}, error) //TODO: is there a way to remove identifier from return val
}

//externalAuthType is the interface for authentication for auth types which are external for the system(the users comes from external system).
//these are the different identity providers - illinois_oidc etc
type externalAuthType interface {
	//getLoginUrl retrieves and pre-formats a login url and params for the SSO provider
	getLoginURL(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, redirectURI string, l *logs.Log) (string, map[string]interface{}, error)

	//externalLogin logins in the external system and provides the authenticated user
	externalLogin(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, l *logs.Log) (*model.ExternalSystemUser, interface{}, error)

	//userExist checks if the user exists
	userExist(externalUserIdentifier string, authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, l *logs.Log) (*model.Account, error)

	//TODO refresh
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
	//		authType (string): Name of the authentication method for provided creds (eg. "email", "username", "illinois_oidc")
	//		creds (string): Credentials/JSON encoded credential structure defined for the specified auth type
	//		appID (string): ID of the app/client that the user is logging in from
	//		orgID (string): ID of the organization that the user is logging in
	//		params (string): JSON encoded params defined by specified auth type
	//		l (*logs.Log): Log object pointer for request
	//	Returns:
	//		Access token (string): Signed ROKWIRE access token to be used to authorize future requests
	//		Refresh Token (string): Refresh token that can be sent to refresh the access token once it expires
	//		Account (Account): Account object for authenticated user
	//		Params (interface{}): authType-specific set of parameters passed back to client
	Login(authType string, creds string, appID string, orgID string, params string, l *logs.Log) (string, string, string, *model.Account, interface{}, error)

	//Refresh refreshes an access token using a refresh token
	//	Input:
	//		refreshToken (string): Refresh token
	//		l (*logs.Log): Log object pointer for request
	//	Returns:
	//		Access token (string): Signed ROKWIRE access token to be used to authorize future requests
	//		Refresh token (string): Refresh token that can be sent to refresh the access token once it expires
	//		Params (interface{}): authType-specific set of parameters passed back to client
	Refresh(refreshToken string, l *logs.Log) (string, string, interface{}, error)

	//GetLoginURL returns a pre-formatted login url for SSO providers
	//	Input:
	//		authType (string): Name of the authentication method for provided creds (eg. "email", "username", "illinois_oidc")
	//		appID (string): ID of the app/client that the user is logging in from
	//		orgID (string): ID of the organization that the user is logging in
	//		redirectURI (string): Registered redirect URI where client will receive response
	//		l (*loglib.Log): Log object pointer for request
	//	Returns:
	//		Login URL (string): SSO provider login URL to be launched in a browser
	//		Params (map[string]interface{}): Params to be sent in subsequent request (if necessary)
	GetLoginURL(authType string, appID string, orgID string, redirectURI string, l *logs.Log) (string, map[string]interface{}, error)

	//AuthorizeService returns a scoped token for the specified service and the service registration record if authorized or
	//	the service registration record if not. Passing "approvedScopes" will update the service authorization for this user and
	//	return a scoped access token which reflects this change.
	//	Input:
	//		claims (tokenClaims): Claims from un-scoped user access token
	//		serviceID (string): ID of the service to be authorized
	//		approvedScopes ([]string): list of scope strings to be approved
	//		l (*logs.Log): Log object pointer for request
	//	Returns:
	//		Access token (string): Signed scoped access token to be used to authorize requests to the specified service
	//		Approved Scopes ([]authorization.Scope): The approved scopes included in the provided token
	//		Service reg (*model.ServiceReg): The service registration record for the requested service
	AuthorizeService(claims TokenClaims, serviceID string, approvedScopes []authorization.Scope, l *logs.Log) (string, []authorization.Scope, *model.ServiceReg, error)

	//GetScopedAccessToken returns a scoped access token with the requested scopes
	GetScopedAccessToken(claims TokenClaims, serviceID string, scopes []authorization.Scope) (string, error)

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

	//Verify checks the verification code in the credentials collection
	Verify(authenticationType string, appID string, orgID string, identifier string, verification string, l *logs.Log) error
}

//Storage interface to communicate with the storage
type Storage interface {
	RegisterStorageListener(storageListener storage.Listener)

	//AuthTypes
	LoadAuthTypes() ([]model.AuthType, error)

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
	FindCredentialByID(ID string) (*model.Credential, error)
	UpdateCredentialByID(creds *model.Credential) error
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

	//ApplicationTypes
	FindApplicationTypeByIdentifier(identifier string) (*model.ApplicationType, error)

	//ApplicationsOrganizations
	LoadApplicationsOrganizations() ([]model.ApplicationOrganization, error)
}
