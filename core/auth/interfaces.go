package auth

import (
	"core-building-block/core/model"
	"core-building-block/driven/storage"
	"time"

	"github.com/rokmetro/auth-library/authorization"
	"github.com/rokmetro/logging-library/logs"
)

//authType is the interface for authentication mechanisms
type authType interface {
	//check checks the validity of provided credentials
	check(creds string, orgID string, appID string, params string, l *logs.Log) (*model.UserAuth, error)
	//refresh refreshes the access token using provided refresh token
	refresh(params map[string]interface{}, orgID string, appID string, l *logs.Log) (*model.UserAuth, error)
	//getLoginUrl retrieves and pre-formats a login url and params for the SSO provider
	getLoginURL(orgID string, appID string, redirectURI string, l *logs.Log) (string, map[string]interface{}, error)
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
	//		params (string): JSON encoded params defined by specified auth type
	//		l (*logs.Log): Log object pointer for request
	//	Returns:
	//		Access token (string): Signed ROKWIRE access token to be used to authorize future requests
	//		Refresh Token (string): Refresh token that can be sent to refresh the access token once it expires
	//		User (User): User object for authenticated user
	//		Params (interface{}): authType-specific set of parameters passed back to client
	Login(authType string, creds string, appID string, params string, l *logs.Log) (string, string, *model.User, interface{}, error)

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
	//		redirectURI (string): Registered redirect URI where client will receive response
	//		l (*loglib.Log): Log object pointer for request
	//	Returns:
	//		Login URL (string): SSO provider login URL to be launched in a browser
	//		Params (map[string]interface{}): Params to be sent in subsequent request (if necessary)
	GetLoginURL(authType string, appID string, redirectURI string, l *logs.Log) (string, map[string]interface{}, error)

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
}

//Storage interface to communicate with the storage
type Storage interface {
	RegisterStorageListener(storageListener storage.Listener)

	//AuthTypes
	LoadAuthTypes() ([]model.AuthType, error)

	//Users
	FindUserByAccountID(accountID string) (*model.User, error)
	InsertUser(user *model.User, authCred *model.AuthCreds) (*model.User, error)
	UpdateUser(user *model.User, orgID string, newOrgData *map[string]interface{}) (*model.User, error)
	DeleteUser(id string) error

	//Organizations
	FindOrganization(id string) (*model.Organization, error)

	//Credentials
	FindCredentialsByID(ID string) (*model.AuthCreds, error)
	FindCredentials(orgID string, authType string, params map[string]interface{}) (*model.AuthCreds, error)

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

	//Applications
	FindApplicationByIdentifier(identifier string) (*model.Application, error)
}
