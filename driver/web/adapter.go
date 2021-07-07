package web

import (
	"core-building-block/core"
	"core-building-block/utils"
	"fmt"
	"net/http"

	log "github.com/rokmetro/logging-library/loglib"

	"github.com/casbin/casbin"
	"github.com/gorilla/mux"

	httpSwagger "github.com/swaggo/http-swagger"
)

//Adapter entity
type Adapter struct {
	host                string
	auth                *Auth
	authorization       *casbin.Enforcer
	logger              *log.StandardLogger
	servicesApisHandler ServicesApisHandler
	adminApisHandler    AdminApisHandler
	encApisHandler      EncApisHandler
	bbsApisHandler      BBsApisHandler

	app *core.Application
}

type handlerFunc = func(*log.Log, http.ResponseWriter, *http.Request)

// @title Rokwire Core Building Block API
// @description Rokwire Core Building Block API Documentation.
// @version 1.0.0
// @host localhost:80
// @BasePath /
// @schemes https http

//Start starts the module
func (we Adapter) Start() {

	//add listener to the application
	we.app.AddListener(&AppListener{&we})

	we.auth.Start()

	router := mux.NewRouter().StrictSlash(true)

	// handle apis
	subRouter := router.PathPrefix("/core").Subrouter()
	subRouter.PathPrefix("/doc/ui").Handler(we.serveDocUI())
	subRouter.HandleFunc("/doc", we.serveDoc)
	subRouter.HandleFunc("/version", we.wrapFunc(we.servicesApisHandler.SerVersion)).Methods("GET")

	///services ///
	servicesSubRouter := subRouter.PathPrefix("/services").Subrouter()

	//auth
	authSubrouter := servicesSubRouter.PathPrefix("/auth").Subrouter()
	authSubrouter.HandleFunc("/test", we.wrapFunc(we.servicesApisHandler.GetAuthTest)).Methods("GET")

	//common
	commonSubrouter := servicesSubRouter.PathPrefix("/common").Subrouter()
	commonSubrouter.HandleFunc("/test", we.wrapFunc(we.servicesApisHandler.GetCommonTest)).Methods("GET")
	///

	///admin ///
	adminSubrouter := subRouter.PathPrefix("/admin").Subrouter()
	adminSubrouter.HandleFunc("/test", we.wrapFunc(we.adminApisHandler.GetTest)).Methods("GET")
	adminSubrouter.HandleFunc("/test-model", we.wrapFunc(we.adminApisHandler.GetTestModel)).Methods("GET")

	adminSubrouter.HandleFunc("/global-config", we.wrapFunc(we.adminApisHandler.CreateGlobalConfig)).Methods("POST")
	adminSubrouter.HandleFunc("/global-config", we.wrapFunc(we.adminApisHandler.GetGlobalConfig)).Methods("GET")
	adminSubrouter.HandleFunc("/global-config", we.wrapFunc(we.adminApisHandler.UpdateGlobalConfig)).Methods("PUT")

	adminSubrouter.HandleFunc("/organizations", we.wrapFunc(we.adminApisHandler.CreateOrganization)).Methods("POST")
	///

	///enc ///
	encSubrouter := subRouter.PathPrefix("/enc").Subrouter()
	encSubrouter.HandleFunc("/test", we.wrapFunc(we.encApisHandler.GetTest)).Methods("GET")
	///

	///bbs ///
	bbsSubrouter := subRouter.PathPrefix("/bbs").Subrouter()
	bbsSubrouter.HandleFunc("/test", we.wrapFunc(we.bbsApisHandler.GetTest)).Methods("GET")
	///

	//TODO
	//we.logger.Fatal(http.ListenAndServe(":80", router))
	http.ListenAndServe(":80", router)
}

func (we Adapter) serveDoc(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("access-control-allow-origin", "*")
	http.ServeFile(w, r, "./docs/swagger.yaml")
}

func (we Adapter) serveDocUI() http.Handler {
	url := fmt.Sprintf("%s/doc", we.host)
	return httpSwagger.Handler(httpSwagger.URL(url))
}

func (we Adapter) wrapFunc(handler handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		utils.LogRequest(req)
		var logObj = we.logger.NewRequestLog(req)

		handler(logObj, w, req)
		logObj.PrintContext()
	}
}

//NewWebAdapter creates new WebAdapter instance
func NewWebAdapter(app *core.Application, host string, logger *log.StandardLogger) Adapter {
	auth := NewAuth(app)
	authorization := casbin.NewEnforcer("driver/web/authorization_model.conf", "driver/web/authorization_policy.csv")

	servicesApisHandler := NewServicesApisHandler(app)
	adminApisHandler := NewAdminApisHandler(app)
	encApisHandler := NewEncApisHandler(app)
	bbsApisHandler := NewBBsApisHandler(app)
	return Adapter{host: host, auth: auth, logger: logger, authorization: authorization, servicesApisHandler: servicesApisHandler,
		adminApisHandler: adminApisHandler, encApisHandler: encApisHandler, bbsApisHandler: bbsApisHandler, app: app}
}

//AppListener implements core.ApplicationListener interface
type AppListener struct {
	adapter *Adapter
}
