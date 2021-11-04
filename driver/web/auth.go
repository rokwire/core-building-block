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
	typeCheckAdminPermission          logutils.MessageActionType = "checking admin permission"
	typeCheckAdminAuthRequestToken    logutils.MessageActionType = "checking admin auth"
	typeCheckServicesScope            logutils.MessageActionType = "checking services scope"
	typeCheckServicesAuthRequestToken logutils.MessageActionType = "checking services auth"
)

//Auth handler
type Auth struct {
	servicesAuth     *ServicesAuth
	servicesUserAuth *ServicesUserAuth
	adminAuth        *AdminAuth
	encAuth          *EncAuth
	bbsAuth          *BBsAuth
	systemAuth       *SystemAuth

	logger *logs.Logger
}

// Authorization is an interface for auth types
type Authorization interface {
	check(req *http.Request) (int, *tokenauth.Claims, error)
}

//Start starts the auth module
func (auth *Auth) Start() error {
	auth.logger.Info("Auth -> start")

	auth.servicesAuth.start()
	auth.servicesUserAuth.start()
	auth.adminAuth.start()
	auth.encAuth.start()
	auth.bbsAuth.start()
	auth.systemAuth.start()

	return nil
}

//NewAuth creates new auth handler
func NewAuth(coreAPIs *core.APIs, serviceID string, authService *authservice.AuthService, logger *logs.Logger) (*Auth, error) {
	servicesAuth, err := newServicesAuth(coreAPIs, authService, serviceID, logger)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "auth handler", nil, err)
	}
	servicesUserAuth := newServicesUserAuth(*servicesAuth)

	adminAuth, err := newAdminAuth(coreAPIs, authService, logger)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "auth handler", nil, err)
	}
	encAuth := newEncAuth(coreAPIs, logger)
	bbsAuth := newBBsAuth(coreAPIs, logger)
	systemAuth, err := newSystemAuth(authService, logger)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "auth handler", nil, err)
	}

	auth := Auth{servicesAuth: servicesAuth, servicesUserAuth: servicesUserAuth, adminAuth: adminAuth, encAuth: encAuth, bbsAuth: bbsAuth, systemAuth: systemAuth,
		logger: logger}

	return &auth, nil
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

	err = auth.tokenAuth.AuthorizeRequestScope(claims, req)
	if err != nil {
		return http.StatusForbidden, nil, errors.WrapErrorAction(typeCheckServicesScope, logutils.TypeRequest, nil, err)
	}

	return http.StatusOK, claims, nil
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

//ServicesUserAuth entity
type ServicesUserAuth struct {
	servicesAuth ServicesAuth
}

func (auth *ServicesUserAuth) start() {
	auth.servicesAuth.logger.Info("ServicesUserAuth -> start")
}

func (auth *ServicesUserAuth) check(req *http.Request) (int, *tokenauth.Claims, error) {
	status, claims, err := auth.servicesAuth.check(req)

	if err == nil && claims != nil {
		if claims.Anonymous {
			return http.StatusForbidden, nil, errors.New("token must not be anonymous")
		}
	}

	return status, claims, err
}

func newServicesUserAuth(servicesAuth ServicesAuth) *ServicesUserAuth {
	auth := ServicesUserAuth{servicesAuth: servicesAuth}
	return &auth
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
	err = auth.tokenAuth.AuthorizeRequestPermissions(claims, req)
	if err != nil {
		return http.StatusForbidden, nil, errors.WrapErrorAction(typeCheckAdminPermission, logutils.TypeRequest, nil, err)
	}

	return http.StatusOK, claims, nil
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
	//TODO
	tokenAuth *tokenauth.TokenAuth
	logger    *logs.Logger
}

func (auth *SystemAuth) start() {
	auth.logger.Info("SystemAuth -> start")
}

func (auth *SystemAuth) check(req *http.Request) (int, *tokenauth.Claims, error) {
	return 0, nil, nil
}

func newSystemAuth(authService *authservice.AuthService, logger *logs.Logger) (*SystemAuth, error) {
	systemPermissionAuth := authorization.NewCasbinStringAuthorization("driver/web/authorization_system_policy.csv")
	systemTokenAuth, err := tokenauth.NewTokenAuth(true, authService, systemPermissionAuth, nil)

	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "token auth for adminAuth", nil, err)
	}

	auth := SystemAuth{tokenAuth: systemTokenAuth, logger: logger}
	return &auth, nil
}
