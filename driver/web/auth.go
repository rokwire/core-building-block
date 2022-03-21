package web

import (
	"core-building-block/core"
	"net/http"

	"github.com/rokwire/core-auth-library-go/authorization"
	"github.com/rokwire/core-auth-library-go/authservice"
	"github.com/rokwire/core-auth-library-go/tokenauth"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

const (
	typeCheckPermission               logutils.MessageActionType = "checking permission"
	typeCheckScope                    logutils.MessageActionType = "checking scope"
	typeCheckAdminAuthRequestToken    logutils.MessageActionType = "checking admin auth"
	typeCheckServicesAuthRequestToken logutils.MessageActionType = "checking services auth"
)

//Auth handler
type Auth struct {
	services   *TokenAuthHandlers
	admin      *TokenAuthHandlers
	encAuth    *EncAuth
	bbsAuth    *BBsAuth
	systemAuth *TokenAuthHandlers

	logger *logs.Logger
}

//Authorization is an interface for auth types
type Authorization interface {
	check(req *http.Request) (int, *tokenauth.Claims, error)
	start()
}

//TokenAuthorization is an interface for auth types
type TokenAuthorization interface {
	Authorization
	getTokenAuth() *tokenauth.TokenAuth
}

//Start starts the auth module
func (auth *Auth) Start() error {
	auth.logger.Info("Auth -> start")

	auth.services.start()
	auth.admin.start()
	auth.encAuth.start()
	auth.bbsAuth.start()
	auth.systemAuth.start()

	return nil
}

//NewAuth creates new auth handler
func NewAuth(coreAPIs *core.APIs, serviceID string, authService *authservice.AuthService, logger *logs.Logger) (*Auth, error) {
	servicesAuth, err := newServicesAuth(coreAPIs, authService, serviceID, logger)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, "services auth", nil, err)
	}
	serviceHandlers, err := newTokenAuthHandlers(servicesAuth)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "services auth handlers", nil, err)
	}

	adminAuth, err := newAdminAuth(coreAPIs, authService, logger)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "admin auth", nil, err)
	}
	adminHandlers, err := newTokenAuthHandlers(adminAuth)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "admin auth handlers", nil, err)
	}

	encAuth := newEncAuth(coreAPIs, logger)
	bbsAuth := newBBsAuth(coreAPIs, logger)
	systemAuth, err := newSystemAuth(coreAPIs, authService, logger)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "auth handler", nil, err)
	}
	systemHandlers, err := newTokenAuthHandlers(systemAuth)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "system auth handlers", nil, err)
	}

	auth := Auth{services: serviceHandlers, admin: adminHandlers, encAuth: encAuth, bbsAuth: bbsAuth, systemAuth: systemHandlers, logger: logger}

	return &auth, nil
}

//TokenAuthHandlers represents token auth handlers
type TokenAuthHandlers struct {
	standard      TokenAuthorization
	permissions   *PermissionsAuth
	user          *UserAuth
	authenticated *AuthenticatedAuth
}

func (auth *TokenAuthHandlers) start() {
	auth.standard.start()
	auth.permissions.start()
	auth.user.start()
	auth.authenticated.start()
}

//newTokenAuthHandlers creates new auth handlers for a
func newTokenAuthHandlers(auth TokenAuthorization) (*TokenAuthHandlers, error) {
	permissionsAuth := newPermissionsAuth(auth)
	userAuth := newUserAuth(auth)
	authenticatedAuth := newAuthenticatedAuth(*userAuth)

	authWrappers := TokenAuthHandlers{standard: auth, permissions: permissionsAuth, user: userAuth, authenticated: authenticatedAuth}
	return &authWrappers, nil
}

//ServicesAuth entity
type ServicesAuth struct {
	coreAPIs  *core.APIs
	tokenAuth *tokenauth.TokenAuth
	logger    *logs.Logger
}

func (auth *ServicesAuth) start() {
	auth.logger.Info("ServicesAuth -> start")
}

func (auth *ServicesAuth) check(req *http.Request) (int, *tokenauth.Claims, error) {
	claims, err := auth.tokenAuth.CheckRequestTokens(req)
	if err != nil {
		return http.StatusUnauthorized, nil, errors.WrapErrorAction(typeCheckServicesAuthRequestToken, logutils.TypeToken, nil, err)
	}

	if claims.Admin {
		return http.StatusUnauthorized, nil, errors.ErrorData(logutils.StatusInvalid, "admin claim", nil)
	}

	err = auth.tokenAuth.AuthorizeRequestScope(claims, req)
	if err != nil {
		return http.StatusForbidden, nil, errors.WrapErrorAction(typeCheckScope, logutils.TypeRequest, nil, err)
	}

	return http.StatusOK, claims, nil
}

func (auth *ServicesAuth) getTokenAuth() *tokenauth.TokenAuth {
	return auth.tokenAuth
}

func newServicesAuth(coreAPIs *core.APIs, authService *authservice.AuthService, serviceID string, logger *logs.Logger) (*ServicesAuth, error) {
	servicesScopeAuth := authorization.NewCasbinScopeAuthorization("driver/web/authorization_services_policy.csv", serviceID)

	servicesTokenAuth, err := tokenauth.NewTokenAuth(true, authService, nil, servicesScopeAuth)

	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "token auth for servicesAuth", nil, err)
	}

	auth := ServicesAuth{coreAPIs: coreAPIs, tokenAuth: servicesTokenAuth, logger: logger}
	return &auth, nil
}

//AdminAuth entity
type AdminAuth struct {
	coreAPIs  *core.APIs
	tokenAuth *tokenauth.TokenAuth
	logger    *logs.Logger
}

func (auth *AdminAuth) start() {
	auth.logger.Info("AdminAuth -> start")
}

func (auth *AdminAuth) check(req *http.Request) (int, *tokenauth.Claims, error) {
	claims, err := auth.tokenAuth.CheckRequestTokens(req)
	if err != nil {
		return http.StatusUnauthorized, nil, errors.WrapErrorAction(typeCheckAdminAuthRequestToken, logutils.TypeToken, nil, err)
	}

	if !claims.Admin {
		return http.StatusUnauthorized, nil, errors.ErrorData(logutils.StatusInvalid, "admin claim", nil)
	}

	return http.StatusOK, claims, nil
}

func (auth *AdminAuth) getTokenAuth() *tokenauth.TokenAuth {
	return auth.tokenAuth
}

func newAdminAuth(coreAPIs *core.APIs, authService *authservice.AuthService, logger *logs.Logger) (*AdminAuth, error) {
	adminPermissionAuth := authorization.NewCasbinStringAuthorization("driver/web/authorization_admin_policy.csv")
	adminTokenAuth, err := tokenauth.NewTokenAuth(true, authService, adminPermissionAuth, nil)

	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "token auth for adminAuth", nil, err)
	}

	auth := AdminAuth{coreAPIs: coreAPIs, tokenAuth: adminTokenAuth, logger: logger}
	return &auth, nil
}

//EncAuth entity
type EncAuth struct {
	coreAPIs *core.APIs

	logger *logs.Logger
}

func (auth *EncAuth) start() {
	auth.logger.Info("EncAuth -> start")
}

func newEncAuth(coreAPIs *core.APIs, logger *logs.Logger) *EncAuth {
	auth := EncAuth{coreAPIs: coreAPIs, logger: logger}
	return &auth
}

//BBsAuth entity
type BBsAuth struct {
	coreAPIs *core.APIs

	logger *logs.Logger
}

func (auth *BBsAuth) start() {
	auth.logger.Info("BBsAuth -> start")
}

func newBBsAuth(coreAPIs *core.APIs, logger *logs.Logger) *BBsAuth {
	auth := BBsAuth{coreAPIs: coreAPIs, logger: logger}
	return &auth
}

//SystemAuth entity
type SystemAuth struct {
	coreAPIs  *core.APIs
	tokenAuth *tokenauth.TokenAuth
	logger    *logs.Logger
}

func (auth *SystemAuth) start() {
	auth.logger.Info("SystemAuth -> start")
}

func (auth *SystemAuth) check(req *http.Request) (int, *tokenauth.Claims, error) {
	claims, err := auth.tokenAuth.CheckRequestTokens(req)
	if err != nil {
		return http.StatusUnauthorized, nil, errors.WrapErrorAction(typeCheckAdminAuthRequestToken, logutils.TypeToken, nil, err)
	}

	if !claims.Admin {
		return http.StatusUnauthorized, nil, errors.ErrorData(logutils.StatusInvalid, "admin claim", nil)
	}

	// TODO: use system flag in token claims rather than orgID matching
	if claims.OrgID != auth.coreAPIs.SystemOrgID {
		return http.StatusUnauthorized, nil, errors.ErrorData(logutils.StatusInvalid, "org id", logutils.StringArgs(claims.OrgID))
	}

	return http.StatusOK, claims, nil
}

func (auth *SystemAuth) getTokenAuth() *tokenauth.TokenAuth {
	return auth.tokenAuth
}

func newSystemAuth(coreAPIs *core.APIs, authService *authservice.AuthService, logger *logs.Logger) (*SystemAuth, error) {
	systemPermissionAuth := authorization.NewCasbinStringAuthorization("driver/web/authorization_system_policy.csv")
	systemTokenAuth, err := tokenauth.NewTokenAuth(true, authService, systemPermissionAuth, nil)

	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "token auth for adminAuth", nil, err)
	}

	auth := SystemAuth{coreAPIs: coreAPIs, tokenAuth: systemTokenAuth, logger: logger}
	return &auth, nil
}

//PermissionsAuth entity
//This enforces that the user has permissions matching the policy
type PermissionsAuth struct {
	auth TokenAuthorization
}

func (a *PermissionsAuth) start() {}

func (a *PermissionsAuth) check(req *http.Request) (int, *tokenauth.Claims, error) {
	status, claims, err := a.auth.check(req)

	if err == nil && claims != nil {
		err = a.auth.getTokenAuth().AuthorizeRequestPermissions(claims, req)
		if err != nil {
			return http.StatusForbidden, nil, errors.WrapErrorAction(typeCheckPermission, logutils.TypeRequest, nil, err)
		}
	}

	return status, claims, err
}

func newPermissionsAuth(auth TokenAuthorization) *PermissionsAuth {
	permissionsAuth := PermissionsAuth{auth: auth}
	return &permissionsAuth
}

//UserAuth entity
// This enforces that the user is not anonymous
type UserAuth struct {
	auth Authorization
}

func (a *UserAuth) start() {}

func (a *UserAuth) check(req *http.Request) (int, *tokenauth.Claims, error) {
	status, claims, err := a.auth.check(req)

	if err == nil && claims != nil {
		if claims.Anonymous {
			return http.StatusForbidden, nil, errors.New("token must not be anonymous")
		}
	}

	return status, claims, err
}

func newUserAuth(auth Authorization) *UserAuth {
	userAuth := UserAuth{auth: auth}
	return &userAuth
}

//AuthenticatedAuth entity
// This enforces that the token was the result of direct user authentication. It should be used to protect sensitive account settings
type AuthenticatedAuth struct {
	userAuth UserAuth
}

func (auth *AuthenticatedAuth) start() {}

func (auth *AuthenticatedAuth) check(req *http.Request) (int, *tokenauth.Claims, error) {
	status, claims, err := auth.userAuth.check(req)

	if err == nil && claims != nil {
		if !claims.Authenticated {
			return http.StatusForbidden, nil, errors.New("user must login again")
		}
	}

	return status, claims, err
}

func newAuthenticatedAuth(userAuth UserAuth) *AuthenticatedAuth {
	auth := AuthenticatedAuth{userAuth: userAuth}
	return &auth
}
