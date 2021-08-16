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
	check(req *http.Request) (int, error)
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
func NewAuth(coreAPIs *core.APIs, serviceID string, authService *authservice.AuthService, logger *logs.Logger) *Auth {
	servicesAuth := newServicesAuth(coreAPIs, authService, serviceID, logger)
	adminAuth := newAdminAuth(coreAPIs, authService, logger)
	encAuth := newEncAuth(coreAPIs, logger)
	bbsAuth := newBBsAuth(coreAPIs, logger)

	auth := Auth{servicesAuth: servicesAuth, adminAuth: adminAuth, encAuth: encAuth, bbsAuth: bbsAuth, logger: logger}

	return &auth
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

func (auth *ServicesAuth) check(req *http.Request) (int, error) {
	claims, err := auth.tokenAuth.CheckRequestTokens(req)
	if err != nil {
		return http.StatusUnauthorized, errors.WrapErrorAction(typeCheckServicesAuthRequestToken, logutils.TypeToken, nil, err)
	}

	err = auth.tokenAuth.AuthorizeRequestScope(claims, req)
	if err != nil {
		return http.StatusForbidden, errors.WrapErrorAction(typeCheckServicesScope, logutils.TypeRequest, nil, err)
	}

	return http.StatusOK, nil
}

func newServicesAuth(coreAPIs *core.APIs, authService *authservice.AuthService, serviceID string, logger *logs.Logger) *ServicesAuth {
	servicesScopeAuth := authorization.NewCasbinScopeAuthorization("driver/web/scope_authorization_policy_services_auth.csv", serviceID)

	servicesTokenAuth, err := tokenauth.NewTokenAuth(true, authService, nil, servicesScopeAuth)

	if err != nil {
		// log.Fatalf("Error intitializing token auth for servicesAuth: %v", err)
	}

	auth := ServicesAuth{coreAPIs: coreAPIs, tokenAuth: servicesTokenAuth, logger: logger}
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

func (auth *AdminAuth) check(req *http.Request) (int, error) {
	claims, err := auth.tokenAuth.CheckRequestTokens(req)
	if err != nil {
		return http.StatusUnauthorized, errors.WrapErrorAction(typeCheckAdminAuthRequestToken, logutils.TypeToken, nil, err)
	}
	err = auth.tokenAuth.AuthorizeRequestPermissions(claims, req)
	if err != nil {
		return http.StatusForbidden, errors.WrapErrorAction(typeCheckAdminPermission, logutils.TypeRequest, nil, err)
	}

	return http.StatusOK, nil
}

func newAdminAuth(coreAPIs *core.APIs, authService *authservice.AuthService, logger *logs.Logger) *AdminAuth {
	adminPermissionAuth := authorization.NewCasbinAuthorization("driver/web/permission_authorization_policy_admin_auth.csv")
	adminTokenAuth, err := tokenauth.NewTokenAuth(true, authService, adminPermissionAuth, nil)

	if err != nil {
		errors.Newf("Error intitializing token auth for adminAuth: %v", err)
	}

	auth := AdminAuth{coreAPIs: coreAPIs, tokenAuth: adminTokenAuth, logger: logger}
	return &auth
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
