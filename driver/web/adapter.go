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
	encApisHandler      EncApisHandler
	bbsApisHandler      BBsApisHandler

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
	adminSubrouter.HandleFunc("/config", we.wrapFunc(we.adminApisHandler.GetGlobalConfigs)).Methods("GET")
	adminSubrouter.HandleFunc("/global-config", we.wrapFunc(we.adminApisHandler.UpdateGlobalConfig)).Methods("PUT")

	///

	///enc ///
	encSubrouter := subRouter.PathPrefix("/enc").Subrouter()
	encSubrouter.HandleFunc("/test", we.wrapFunc(we.encApisHandler.GetTest)).Methods("GET")
	///

	///bbs ///
	bbsSubrouter := subRouter.PathPrefix("/bbs").Subrouter()
	bbsSubrouter.HandleFunc("/test", we.wrapFunc(we.bbsApisHandler.GetTest)).Methods("GET")
	///

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

type loggingFunc = func(utils.Logging, http.ResponseWriter, *http.Request)

func (we Adapter) wrapFunc(handler loggingFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

		//generate logging ID
		//loggingID, _ := utils.NewUUID()
		loggingID := "1234"
		logging := utils.Logging{ID: loggingID}

		//log for first time
		data := utils.GetRequestLogData(req)
		logging.Printf(data)

		//TODO get user id:
		userID := " "
		logging.UserID = userID

		//log for second time
		logging.Printf("Already have user id")

		handler(logging, w, req)
	}
}

//NewWebAdapter creates new WebAdapter instance
func NewWebAdapter(app *core.Application, host string) Adapter {
	auth := NewAuth(app)
	authorization := casbin.NewEnforcer("driver/web/authorization_model.conf", "driver/web/authorization_policy.csv")

	servicesApisHandler := NewServicesApisHandler(app)
	adminApisHandler := NewAdminApisHandler(app)
	encApisHandler := NewEncApisHandler(app)
	bbsApisHandler := NewBBsApisHandler(app)
	return Adapter{host: host, auth: auth, authorization: authorization, servicesApisHandler: servicesApisHandler,
		adminApisHandler: adminApisHandler, encApisHandler: encApisHandler, bbsApisHandler: bbsApisHandler, app: app}
}

//AppListener implements core.ApplicationListener interface
type AppListener struct {
	adapter *Adapter
}
