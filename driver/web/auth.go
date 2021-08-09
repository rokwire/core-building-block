package web

import (
	"core-building-block/core"
	"log"
	"net/http"

	"github.com/rokmetro/auth-library/authorization"
	"github.com/rokmetro/auth-library/authservice"
	"github.com/rokmetro/auth-library/tokenauth"
	"github.com/rokmetro/logging-library/errors"
	"github.com/rokmetro/logging-library/logutils"
)

const (
	typeCheckAdminPermission          logutils.MessageActionType = "checking admin permission"
	typeCheckAdminAuthRequestToken    logutils.MessageActionType = "checking admin auth request token"
	typeCheckServicesScope            logutils.MessageActionType = "checking services scope"
	typeCheckServicesAuthRequestToken logutils.MessageActionType = "checking services auth request token"
)

//Auth handler
type Auth struct {
	authService  *authservice.AuthService
	servicesAuth *ServicesAuth
	adminAuth    *AdminAuth
	encAuth      *EncAuth
	bbsAuth      *BBsAuth
}

// Authorization is an interface for auth types
type Authorization interface {
	check(req *http.Request) (int, error)
}

//Start starts the auth module
func (auth *Auth) Start() error {
	log.Println("Auth -> start")

	auth.servicesAuth.start()
	auth.adminAuth.start()
	auth.encAuth.start()
	auth.bbsAuth.start()

	return nil
}

//NewAuth creates new auth handler
func NewAuth(coreAPIs *core.APIs, serviceID string, authService *authservice.AuthService) *Auth {
	servicesAuth := newServicesAuth(coreAPIs, authService, serviceID)
	adminAuth := newAdminAuth(coreAPIs, authService)
	encAuth := newEncAuth(coreAPIs)
	bbsAuth := newBBsAuth(coreAPIs)

	auth := Auth{servicesAuth: servicesAuth, adminAuth: adminAuth, encAuth: encAuth, bbsAuth: bbsAuth}

	return &auth
}

//ServicesAuth entity
type ServicesAuth struct {
	coreAPIs  *core.APIs
	tokenAuth *tokenauth.TokenAuth
	scopeAuth Authorization
}

func (auth *ServicesAuth) start() {
	log.Println("ServicesAuth -> start")
}

func (auth *ServicesAuth) check(req *http.Request) (int, error) {
	claims, err := auth.tokenAuth.CheckRequestTokens(req)
	if err != nil {
		return http.StatusUnauthorized, errors.WrapErrorAction(typeCheckServicesAuthRequestToken, logutils.TypeRequest, nil, err)
	}

	err = auth.tokenAuth.AuthorizeRequestScope(claims, req)
	if err != nil {
		return http.StatusForbidden, errors.WrapErrorAction(typeCheckServicesScope, logutils.TypeRequest, nil, err)
	}

	return http.StatusOK, nil
}

func newServicesAuth(coreAPIs *core.APIs, authService *authservice.AuthService, serviceID string) *ServicesAuth {
	servicesScopeAuth := authorization.NewCasbinScopeAuthorization("./scope_authorization_policy_services_auth.csv", serviceID)

	servicesTokenAuth, err := tokenauth.NewTokenAuth(true, authService, nil, servicesScopeAuth)

	if err != nil {
		// log.Fatalf("Error intitializing token auth for servicesAuth: %v", err)
	}

	auth := ServicesAuth{coreAPIs: coreAPIs, tokenAuth: servicesTokenAuth}
	return &auth
}

//AdminAuth entity
type AdminAuth struct {
	coreAPIs       *core.APIs
	tokenAuth      *tokenauth.TokenAuth
	permissionAuth Authorization
}

func (auth *AdminAuth) start() {
	log.Println("AdminAuth -> start")
}

func (auth *AdminAuth) check(req *http.Request) (int, error) {
	// Authenticate token
	claims, err := auth.tokenAuth.CheckRequestTokens(req)
	if err != nil {
		// logObj.RequestErrorAction(w, typeAdminAuthRequestToken, logutils.TypeToken, nil, err, http.StatusUnauthorized, true)
		return http.StatusUnauthorized, errors.WrapErrorAction(typeCheckAdminAuthRequestToken, logutils.TypeRequest, nil, err)
	}
	err = auth.tokenAuth.AuthorizeRequestPermissions(claims, req)
	if err != nil {
		// logObj.RequestErrorAction(w, typeAdminAuthentication, logutils.TypeClaims, nil, err, http.StatusForbidden, true)
		return http.StatusForbidden, errors.WrapErrorAction(typeCheckAdminPermission, logutils.TypeRequest, nil, err)
	}

	return http.StatusOK, nil
}

func newAdminAuth(coreAPIs *core.APIs, authService *authservice.AuthService) *AdminAuth {
	adminPermissionAuth := authorization.NewCasbinAuthorization("./permission_authorization_policy_admin_auth.csv")

	adminTokenAuth, err := tokenauth.NewTokenAuth(true, authService, adminPermissionAuth, nil)

	if err != nil {
		// log.Fatalf("Error intitializing token auth for adminAuth: %v", err)
	}

	auth := AdminAuth{coreAPIs: coreAPIs, tokenAuth: adminTokenAuth}
	return &auth
}

//EncAuth entity
type EncAuth struct {
	coreAPIs *core.APIs
}

func (auth *EncAuth) start() {
	log.Println("EncAuth -> start")
}

func newEncAuth(coreAPIs *core.APIs) *EncAuth {
	auth := EncAuth{coreAPIs: coreAPIs}
	return &auth
}

//BBsAuth entity
type BBsAuth struct {
	coreAPIs *core.APIs
}

func (auth *BBsAuth) start() {
	log.Println("BBsAuth -> start")
}

func newBBsAuth(coreAPIs *core.APIs) *BBsAuth {
	auth := BBsAuth{coreAPIs: coreAPIs}
	return &auth
}
