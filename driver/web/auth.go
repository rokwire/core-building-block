package web

import (
	"core-building-block/core"
	"log"

	"github.com/rokmetro/auth-library/authorization"
	"github.com/rokmetro/auth-library/authservice"
	"github.com/rokmetro/auth-library/tokenauth"
)

//Auth handler
type Auth struct {
	authService  *authservice.AuthService
	servicesAuth *ServicesAuth
	adminAuth    *AdminAuth
	encAuth      *EncAuth
	bbsAuth      *BBsAuth
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
	servicesScopeAuth := authorization.NewCasbinScopeAuthorization("./permissions_authorization_policy_services_auth.csv", serviceID)
	servicesTokenAuth, err := tokenauth.NewTokenAuth(true, authService, nil, servicesScopeAuth)
	if err != nil {
		log.Fatalf("Error intitializing token auth for servicesAuth: %v", err)
	}
	servicesAuth := newServicesAuth(coreAPIs, servicesTokenAuth)

	adminPermissionAuth := authorization.NewCasbinAuthorization("./scope_authorization_policy_admin_auth.csv")
	adminTokenAuth, err := tokenauth.NewTokenAuth(true, authService, adminPermissionAuth, nil)
	if err != nil {
		log.Fatalf("Error intitializing token auth for adminAuth: %v", err)
	}
	adminAuth := newAdminAuth(coreAPIs, adminTokenAuth)

	encAuth := newEncAuth(coreAPIs)
	bbsAuth := newBBsAuth(coreAPIs)

	auth := Auth{servicesAuth: servicesAuth, adminAuth: adminAuth, encAuth: encAuth, bbsAuth: bbsAuth}

	return &auth
}

//ServicesAuth entity
type ServicesAuth struct {
	coreAPIs  *core.APIs
	tokenAuth *tokenauth.TokenAuth
}

func (auth *ServicesAuth) start() {
	log.Println("ServicesAuth -> start")
}

func newServicesAuth(coreAPIs *core.APIs, tokenAuth *tokenauth.TokenAuth) *ServicesAuth {
	auth := ServicesAuth{coreAPIs: coreAPIs, tokenAuth: tokenAuth}
	return &auth
}

//AdminAuth entity
type AdminAuth struct {
	coreAPIs  *core.APIs
	tokenAuth *tokenauth.TokenAuth
}

func (auth *AdminAuth) start() {
	log.Println("AdminAuth -> start")
}

func newAdminAuth(coreAPIs *core.APIs, tokenAuth *tokenauth.TokenAuth) *AdminAuth {
	auth := AdminAuth{coreAPIs: coreAPIs, tokenAuth: tokenAuth}
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
