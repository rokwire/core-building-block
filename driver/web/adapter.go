package web

import (
	"core-building-block/core"
	"core-building-block/utils"
	"fmt"
	"log"
	"net/http"

	"github.com/casbin/casbin"
	"github.com/gorilla/mux"

	httpSwagger "github.com/swaggo/http-swagger"
)

//Adapter entity
type Adapter struct {
	host          string
	auth          *Auth
	authorization *casbin.Enforcer

	servicesApisHandler ServicesApisHandler
	adminApisHandler    AdminApisHandler

	app *core.Application
}

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
	router.PathPrefix("/doc/ui").Handler(we.serveDocUI())
	router.HandleFunc("/doc", we.serveDoc)

	log.Fatal(http.ListenAndServe(":80", router))
}

func (we Adapter) serveDoc(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("access-control-allow-origin", "*")
	http.ServeFile(w, r, "./docs/swagger.yaml")
}

func (we Adapter) serveDocUI() http.Handler {
	url := fmt.Sprintf("%s/doc", we.host)
	return httpSwagger.Handler(httpSwagger.URL(url))
}

func (we Adapter) wrapFunc(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		utils.LogRequest(req)

		handler(w, req)
	}
}

//NewWebAdapter creates new WebAdapter instance
func NewWebAdapter(app *core.Application, host string) Adapter {
	auth := NewAuth(app)
	authorization := casbin.NewEnforcer("driver/web/authorization_model.conf", "driver/web/authorization_policy.csv")

	servicesApisHandler := NewServicesApisHandler(app)
	adminApisHandler := NewAdminApisHandler(app)
	return Adapter{host: host, auth: auth, authorization: authorization, servicesApisHandler: servicesApisHandler, adminApisHandler: adminApisHandler, app: app}
}

//AppListener implements core.ApplicationListener interface
type AppListener struct {
	adapter *Adapter
}
