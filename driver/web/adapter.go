package web

import (
	"context"
	"core-building-block/core"
	"core-building-block/utils"
	"fmt"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"

	"github.com/gorilla/mux"

	log "github.com/rokmetro/logging-library/loglib"

	"github.com/casbin/casbin"

	httpSwagger "github.com/swaggo/http-swagger"
)

type errorResponse struct {
	error string
	code  int
}

type successResponse struct {
	responseCode int
	body         []byte
	contentType  *string
}

//Adapter entity
type Adapter struct {
	openAPIRouter routers.Router
	host          string
	auth          *Auth
	authorization *casbin.Enforcer
	logger        *log.StandardLogger

	defaultApisHandler  DefaultApisHandler
	servicesApisHandler ServicesApisHandler
	adminApisHandler    AdminApisHandler
	encApisHandler      EncApisHandler
	bbsApisHandler      BBsApisHandler

	coreAPIs *core.APIs
}

type handlerFunc = func(*log.Log, http.ResponseWriter, *http.Request) (*errorResponse, *successResponse)

//Start starts the module
func (we Adapter) Start() {

	//add listener to the application
	we.coreAPIs.AddListener(&AppListener{&we})

	we.auth.Start()

	router := mux.NewRouter().StrictSlash(true)

	// handle apis
	subRouter := router.PathPrefix("/core").Subrouter()
	subRouter.PathPrefix("/doc/ui").Handler(we.serveDocUI())
	subRouter.HandleFunc("/doc", we.serveDoc)

	///default ///
	subRouter.HandleFunc("/version", we.wrapFunc(we.defaultApisHandler.GetVersion)).Methods("GET")
	///

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

	err := http.ListenAndServe(":80", router)
	if err != nil {
		we.logger.Fatal(err.Error())
	}
}

func (we Adapter) serveDoc(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("access-control-allow-origin", "*")
	http.ServeFile(w, r, "./driver/web/docs/def.yaml")
}

func (we Adapter) serveDocUI() http.Handler {
	url := fmt.Sprintf("%s/doc", we.host)
	return httpSwagger.Handler(httpSwagger.URL(url))
}

func (we Adapter) wrapFunc(handler handlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {

		/*
			options := openapi3filter.Options{IncludeResponseStatus: true}
			responseValidationInput := &openapi3filter.ResponseValidationInput{
				RequestValidationInput: requestValidationInput,
				Status:                 200,
				Header:                 http.Header{"Content-Type": []string{"application/json"}},
				Options:                &options,
			}
			responseValidationInput.SetBodyBytes([]byte(`{}`))
			//responseValidationInput.SetBodyBytes([]byte(`fwefwefwefewfew`))

			err = openapi3filter.ValidateResponse(context.Background(), responseValidationInput)
			if err != nil {
				panic(err)
			}
			/// */

		utils.LogRequest(req)
		var logObj = we.logger.NewRequestLog(req)

		//validate request
		err := we.validateRequest(req)
		if err != nil {
			we.logger.Errorf("error validating request - %s", err)

			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(http.StatusText(http.StatusBadRequest)))
			return
		}

		errorResp, successResp := handler(logObj, w, req)
		//return the error response if there is
		if errorResp != nil {
			we.logger.Errorf("error response - %s", errorResp.error)
			http.Error(w, errorResp.error, errorResp.code)
			return
		}

		//return success error
		if successResp.contentType != nil {
			w.Header().Set("Content-Type", *successResp.contentType)
		}
		w.WriteHeader(successResp.responseCode)
		if successResp.body != nil {
			w.Write(successResp.body)
		}

		//TODO
		logObj.PrintContext()
	}
}

func (we Adapter) validateRequest(req *http.Request) error {
	route, pathParams, err := we.openAPIRouter.FindRoute(req)
	if err != nil {
		return err
	}

	requestValidationInput := &openapi3filter.RequestValidationInput{
		Request:    req,
		PathParams: pathParams,
		Route:      route,
	}
	if err := openapi3filter.ValidateRequest(context.Background(), requestValidationInput); err != nil {
		return err
	}
	return nil
}

//NewWebAdapter creates new WebAdapter instance
func NewWebAdapter(coreAPIs *core.APIs, host string, logger *log.StandardLogger) Adapter {
	//openAPI doc
	loader := &openapi3.Loader{Context: context.Background(), IsExternalRefsAllowed: true}
	doc, err := loader.LoadFromFile("driver/web/docs/def.yaml")
	if err != nil {
		logger.Fatal(err.Error())
	}
	err = doc.Validate(loader.Context)
	if err != nil {
		logger.Fatal(err.Error())
	}
	openAPIRouter, err := gorillamux.NewRouter(doc)
	if err != nil {
		logger.Fatal(err.Error())
	}
	//

	auth := NewAuth(coreAPIs)
	authorization := casbin.NewEnforcer("driver/web/authorization_model.conf", "driver/web/authorization_policy.csv")

	defaultApisHandler := NewDefaultApisHandler(coreAPIs)
	servicesApisHandler := NewServicesApisHandler(coreAPIs)
	adminApisHandler := NewAdminApisHandler(coreAPIs)
	encApisHandler := NewEncApisHandler(coreAPIs)
	bbsApisHandler := NewBBsApisHandler(coreAPIs)
	return Adapter{openAPIRouter: openAPIRouter, host: host, auth: auth, logger: logger, authorization: authorization, defaultApisHandler: defaultApisHandler,
		servicesApisHandler: servicesApisHandler, adminApisHandler: adminApisHandler, encApisHandler: encApisHandler, bbsApisHandler: bbsApisHandler, coreAPIs: coreAPIs}
}

//AppListener implements core.ApplicationListener interface
type AppListener struct {
	adapter *Adapter
}

//OnAuthConfigUpdated notifies that an auth config has been updated
func (al *AppListener) OnAuthConfigUpdated() {
	al.adapter.coreAPIs.Auth.LoadAuthConfigs()
}
