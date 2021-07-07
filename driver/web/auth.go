package web

import (
	"core-building-block/core"
	"log"
)

//Auth handler
type Auth struct {
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
func NewAuth(coreAPIs *core.CoreAPIs) *Auth {
	servicesAuth := newServicesAuth(coreAPIs)
	adminAuth := newAdminAuth(coreAPIs)
	encAuth := newEncAuth(coreAPIs)
	bbsAuth := newBBsAuth(coreAPIs)

	auth := Auth{servicesAuth: servicesAuth, adminAuth: adminAuth, encAuth: encAuth, bbsAuth: bbsAuth}
	return &auth
}

//ServicesAuth entity
type ServicesAuth struct {
	coreAPIs *core.CoreAPIs
}

func (auth *ServicesAuth) start() {
	log.Println("ServicesAuth -> start")
}

func newServicesAuth(coreAPIs *core.CoreAPIs) *ServicesAuth {
	auth := ServicesAuth{coreAPIs: coreAPIs}
	return &auth
}

//AdminAuth entity
type AdminAuth struct {
	coreAPIs *core.CoreAPIs
}

func (auth *AdminAuth) start() {
	log.Println("AdminAuth -> start")
}

func newAdminAuth(coreAPIs *core.CoreAPIs) *AdminAuth {
	auth := AdminAuth{coreAPIs: coreAPIs}
	return &auth
}

//EncAuth entity
type EncAuth struct {
	coreAPIs *core.CoreAPIs
}

func (auth *EncAuth) start() {
	log.Println("EncAuth -> start")
}

func newEncAuth(coreAPIs *core.CoreAPIs) *EncAuth {
	auth := EncAuth{coreAPIs: coreAPIs}
	return &auth
}

//BBsAuth entity
type BBsAuth struct {
	coreAPIs *core.CoreAPIs
}

func (auth *BBsAuth) start() {
	log.Println("BBsAuth -> start")
}

func newBBsAuth(coreAPIs *core.CoreAPIs) *BBsAuth {
	auth := BBsAuth{coreAPIs: coreAPIs}
	return &auth
}
