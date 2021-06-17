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
func NewAuth(app *core.Application) *Auth {
	servicesAuth := newServicesAuth(app)
	adminAuth := newAdminAuth(app)
	encAuth := newEncAuth(app)
	bbsAuth := newBBsAuth(app)

	auth := Auth{servicesAuth: servicesAuth, adminAuth: adminAuth, encAuth: encAuth, bbsAuth: bbsAuth}
	return &auth
}

//ServicesAuth entity
type ServicesAuth struct {
	app *core.Application
}

func (auth *ServicesAuth) start() {
	log.Println("ServicesAuth -> start")
}

func newServicesAuth(app *core.Application) *ServicesAuth {
	auth := ServicesAuth{app: app}
	return &auth
}

//AdminAuth entity
type AdminAuth struct {
	app *core.Application
}

func (auth *AdminAuth) start() {
	log.Println("AdminAuth -> start")
}

func newAdminAuth(app *core.Application) *AdminAuth {
	auth := AdminAuth{app: app}
	return &auth
}

//EncAuth entity
type EncAuth struct {
	app *core.Application
}

func (auth *EncAuth) start() {
	log.Println("EncAuth -> start")
}

func newEncAuth(app *core.Application) *EncAuth {
	auth := EncAuth{app: app}
	return &auth
}

//BBsAuth entity
type BBsAuth struct {
	app *core.Application
}

func (auth *BBsAuth) start() {
	log.Println("BBsAuth -> start")
}

func newBBsAuth(app *core.Application) *BBsAuth {
	auth := BBsAuth{app: app}
	return &auth
}

func CreateConfigs(name string, setting string) error {
	return auth.adminAuth.createConfigs(name, setting)
}

func (auth *AdminAuth) createConfigs(name string, setting string) error {
	_, err := auth.app.CreateConfigs(name, setting)
	if err != nil {
		return err
	}

	return nil
}
