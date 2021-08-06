package web

import (
	"core-building-block/core"
	"log"

	"github.com/rokmetro/auth-library/authservice"
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
	servicesAuth := newServicesAuth(coreAPIs)
	adminAuth := newAdminAuth(coreAPIs)
	encAuth := newEncAuth(coreAPIs)
	bbsAuth := newBBsAuth(coreAPIs)

	auth := Auth{servicesAuth: servicesAuth, adminAuth: adminAuth, encAuth: encAuth, bbsAuth: bbsAuth}

	return &auth
}

//ServicesAuth entity
type ServicesAuth struct {
	coreAPIs *core.APIs
}

func (auth *ServicesAuth) start() {
	log.Println("ServicesAuth -> start")
}

func newServicesAuth(coreAPIs *core.APIs) *ServicesAuth {
	auth := ServicesAuth{coreAPIs: coreAPIs}
	return &auth
}

//AdminAuth entity
type AdminAuth struct {
	coreAPIs *core.APIs
}

func (auth *AdminAuth) start() {
	log.Println("AdminAuth -> start")
}

func newAdminAuth(coreAPIs *core.APIs) *AdminAuth {
	auth := AdminAuth{coreAPIs: coreAPIs}
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
