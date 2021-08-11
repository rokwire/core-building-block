package web

import (
	"core-building-block/core"

	"github.com/rokmetro/logging-library/logs"
)

//Auth handler
type Auth struct {
	servicesAuth *ServicesAuth
	adminAuth    *AdminAuth
	encAuth      *EncAuth
	bbsAuth      *BBsAuth

	logger *logs.Logger
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
func NewAuth(coreAPIs *core.APIs, logger *logs.Logger) *Auth {
	servicesAuth := newServicesAuth(coreAPIs, logger)
	adminAuth := newAdminAuth(coreAPIs, logger)
	encAuth := newEncAuth(coreAPIs, logger)
	bbsAuth := newBBsAuth(coreAPIs, logger)

	auth := Auth{servicesAuth: servicesAuth, adminAuth: adminAuth, encAuth: encAuth, bbsAuth: bbsAuth, logger: logger}
	return &auth
}

//ServicesAuth entity
type ServicesAuth struct {
	coreAPIs *core.APIs

	logger *logs.Logger
}

func (auth *ServicesAuth) start() {
	auth.logger.Info("ServicesAuth -> start")
}

func newServicesAuth(coreAPIs *core.APIs, logger *logs.Logger) *ServicesAuth {
	auth := ServicesAuth{coreAPIs: coreAPIs, logger: logger}
	return &auth
}

//AdminAuth entity
type AdminAuth struct {
	coreAPIs *core.APIs

	logger *logs.Logger
}

func (auth *AdminAuth) start() {
	auth.logger.Info("AdminAuth -> start")
}

func newAdminAuth(coreAPIs *core.APIs, logger *logs.Logger) *AdminAuth {
	auth := AdminAuth{coreAPIs: coreAPIs, logger: logger}
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
