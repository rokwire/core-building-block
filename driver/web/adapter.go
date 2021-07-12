package web

import (
	"context"
	"core-building-block/core"
	"core-building-block/utils"
	"fmt"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/gorilla/mux"

	log "github.com/rokmetro/logging-library/loglib"

	"github.com/casbin/casbin"

	httpSwagger "github.com/swaggo/http-swagger"
)

//Adapter entity
type Adapter struct {
	host          string
	auth          *Auth
	authorization *casbin.Enforcer
	logger        *log.StandardLogger

	servicesApisHandler ServicesApisHandler
	adminApisHandler    AdminApisHandler
	encApisHandler      EncApisHandler
	bbsApisHandler      BBsApisHandler

	coreAPIs *core.APIs
}

type handlerFunc = func(*log.Log, http.ResponseWriter, *http.Request)

//Start starts the module
func (we Adapter) Start() {

	//add listener to the application
	we.coreAPIs.AddListener(&AppListener{&we})

	// Output:
	// response body doesn't match the schema: Field must be set to string or not be present
	// Schema:
	//   {
	//     "type": "string"
	//   }
	//
	// Value:
	//   "object"

	/*
		loader := openapi3.NewLoader()
		doc, err := loader.LoadFromFile("docs/def.yaml")
		if err != nil {
			we.logger.Error(err.Error())
		}

		err = doc.Validate(loader.Context)
		if err != nil {
			we.logger.Error(err.Error())
		}
		router, _ := gorillamux.NewRouter(doc)
		//route, pathParams, _ := router.FindRoute(httpRequest)
	*/
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
	adminSubrouter.HandleFunc("/organizations/{id}", we.wrapFunc(we.adminApisHandler.UpdateOrganization)).Methods("PUT")
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
	http.ServeFile(w, r, "./docs/def.yaml")
}

func (we Adapter) serveDocUI() http.Handler {
	url := fmt.Sprintf("%s/doc", we.host)
	return httpSwagger.Handler(httpSwagger.URL(url))
}

func (we Adapter) wrapFunc(handler handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		ctx := context.Background()
		loader := &openapi3.Loader{Context: ctx, IsExternalRefsAllowed: true}
		doc, err := loader.LoadFromFile("docs/def.yaml")
		if err != nil {
			panic(err)
		}
		if err = doc.Validate(loader.Context); err != nil {
			panic(err)
		}
		router5, err := gorillamux.NewRouter(doc)
		if err != nil {
			panic(err)
		}
		//httpReq, err := http.NewRequest(http.MethodGet, "core/admin/organizations/{id}", nil)
		//if err != nil {
		//	panic(err)
		//}

		route, pathParams, err := router5.FindRoute(req)
		if err != nil {
			panic(err)
		}

		requestValidationInput := &openapi3filter.RequestValidationInput{
			Request:    req,
			PathParams: pathParams,
			Route:      route,
		}
		if err := openapi3filter.ValidateRequest(ctx, requestValidationInput); err != nil {
			panic(err)
		}

		options := openapi3filter.Options{IncludeResponseStatus: true}
		responseValidationInput := &openapi3filter.ResponseValidationInput{
			RequestValidationInput: requestValidationInput,
			Status:                 200,
			Header:                 http.Header{"Content-Type": []string{"application/json"}},
			Options:                &options,
		}
		responseValidationInput.SetBodyBytes([]byte(`{}`))
		//responseValidationInput.SetBodyBytes([]byte(`fwefwefwefewfew`))

		err = openapi3filter.ValidateResponse(ctx, responseValidationInput)
		if err != nil {
			panic(err)
		}

		///

		utils.LogRequest(req)
		var logObj = we.logger.NewRequestLog(req)

		handler(logObj, w, req)
		logObj.PrintContext()
	}
}

//NewWebAdapter creates new WebAdapter instance
func NewWebAdapter(coreAPIs *core.APIs, host string, logger *log.StandardLogger) Adapter {
	auth := NewAuth(coreAPIs)
	authorization := casbin.NewEnforcer("driver/web/authorization_model.conf", "driver/web/authorization_policy.csv")

	servicesApisHandler := NewServicesApisHandler(coreAPIs)
	adminApisHandler := NewAdminApisHandler(coreAPIs)
	encApisHandler := NewEncApisHandler(coreAPIs)
	bbsApisHandler := NewBBsApisHandler(coreAPIs)
	return Adapter{host: host, auth: auth, logger: logger, authorization: authorization, servicesApisHandler: servicesApisHandler,
		adminApisHandler: adminApisHandler, encApisHandler: encApisHandler, bbsApisHandler: bbsApisHandler, coreAPIs: coreAPIs}
}

//AppListener implements core.ApplicationListener interface
type AppListener struct {
	adapter *Adapter
}
