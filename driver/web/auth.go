package web

import (
	"core-building-block/core"
	"net/http"

	"github.com/rokmetro/auth-library/authorization"
	"github.com/rokmetro/auth-library/authservice"
	"github.com/rokmetro/auth-library/tokenauth"
	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logs"
	"github.com/rokmetro/logging-library/logutils"
)

const (
	typeCheckAdminPermission          logutils.MessageActionType = "checking admin permission"
	typeCheckAdminAuthRequestToken    logutils.MessageActionType = "checking admin auth"
	typeCheckServicesScope            logutils.MessageActionType = "checking services scope"
	typeCheckServicesAuthRequestToken logutils.MessageActionType = "checking services auth"
)

//Auth handler
type Auth struct {
	authService  *authservice.AuthService
	servicesAuth *ServicesAuth
	adminAuth    *AdminAuth
	encAuth      *EncAuth
	bbsAuth      *BBsAuth

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
	auth.adminAuth.start()
	auth.encAuth.start()
	auth.bbsAuth.start()

	return nil
}

//NewAuth creates new auth handler
func NewAuth(coreAPIs *core.APIs, serviceID string, authService *authservice.AuthService, logger *logs.Logger) (*Auth, error) {
	servicesAuth, err := newServicesAuth(coreAPIs, authService, serviceID, logger)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "auth handler", nil, err)
	}
	adminAuth, err := newAdminAuth(coreAPIs, authService, logger)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "auth handler", nil, err)
	}
	encAuth := newEncAuth(coreAPIs, logger)
	bbsAuth := newBBsAuth(coreAPIs, logger)

	auth := Auth{servicesAuth: servicesAuth, adminAuth: adminAuth, encAuth: encAuth, bbsAuth: bbsAuth, logger: logger}

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
	servicesScopeAuth := authorization.NewCasbinScopeAuthorization("driver/web/scope_authorization_policy_services_auth.csv", serviceID)

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
	err = auth.tokenAuth.AuthorizeRequestPermissions(claims, req)
	if err != nil {
		return http.StatusForbidden, nil, errors.WrapErrorAction(typeCheckAdminPermission, logutils.TypeRequest, nil, err)
	}

	return http.StatusOK, claims, nil
}

func newAdminAuth(coreAPIs *core.APIs, authService *authservice.AuthService, logger *logs.Logger) (*AdminAuth, error) {
	adminPermissionAuth := authorization.NewCasbinAuthorization("driver/web/permission_authorization_policy_admin_auth.csv")
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
