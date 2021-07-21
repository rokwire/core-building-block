package web

import (
	"context"
	"core-building-block/core"
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

//Adapter entity
type Adapter struct {
	env string

	openAPIRouter routers.Router
	host          string
	auth          *Auth
	authorization *casbin.Enforcer
	logger        *log.Logger

	defaultApisHandler  DefaultApisHandler
	servicesApisHandler ServicesApisHandler
	adminApisHandler    AdminApisHandler
	encApisHandler      EncApisHandler
	bbsApisHandler      BBsApisHandler

	coreAPIs *core.APIs
}

type handlerFunc = func(*log.Log, *http.Request) log.HttpResponse

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
	subRouter.HandleFunc("/version", we.wrapFunc(we.defaultApisHandler.getVersion)).Methods("GET")
	///

	///services ///
	servicesSubRouter := subRouter.PathPrefix("/services").Subrouter()

	//auth
	authSubrouter := servicesSubRouter.PathPrefix("/auth").Subrouter()
	authSubrouter.HandleFunc("/test", we.wrapFunc(we.servicesApisHandler.getAuthTest)).Methods("GET")

	//common
	commonSubrouter := servicesSubRouter.PathPrefix("/common").Subrouter()
	commonSubrouter.HandleFunc("/test", we.wrapFunc(we.servicesApisHandler.getCommonTest)).Methods("GET")
	///

	///admin ///
	adminSubrouter := subRouter.PathPrefix("/admin").Subrouter()
	adminSubrouter.HandleFunc("/test", we.wrapFunc(we.adminApisHandler.getTest)).Methods("GET")
	adminSubrouter.HandleFunc("/test-model", we.wrapFunc(we.adminApisHandler.getTestModel)).Methods("GET")

	adminSubrouter.HandleFunc("/global-config", we.wrapFunc(we.adminApisHandler.createGlobalConfig)).Methods("POST")
	adminSubrouter.HandleFunc("/global-config", we.wrapFunc(we.adminApisHandler.getGlobalConfig)).Methods("GET")
	adminSubrouter.HandleFunc("/global-config", we.wrapFunc(we.adminApisHandler.updateGlobalConfig)).Methods("PUT")

	adminSubrouter.HandleFunc("/organizations", we.wrapFunc(we.adminApisHandler.createOrganization)).Methods("POST")
	adminSubrouter.HandleFunc("/organizations/{id}", we.wrapFunc(we.adminApisHandler.updateOrganization)).Methods("PUT")
	///

	///enc ///
	encSubrouter := subRouter.PathPrefix("/enc").Subrouter()
	encSubrouter.HandleFunc("/test", we.wrapFunc(we.encApisHandler.getTest)).Methods("GET")
	///

	///bbs ///
	bbsSubrouter := subRouter.PathPrefix("/bbs").Subrouter()
	bbsSubrouter.HandleFunc("/test", we.wrapFunc(we.bbsApisHandler.getTest)).Methods("GET")
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
		logObj := we.logger.NewRequestLog(req)

		logObj.RequestReceived()

		var err error

		//1. validate request
		var requestValidationInput *openapi3filter.RequestValidationInput
		if we.env != "production" {
			requestValidationInput, err = we.validateRequest(req)
			if err != nil {
				logObj.Errorf("error validating request - %s", err)

				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(http.StatusText(http.StatusBadRequest)))
				return
			}
		}

		//2. process it
		response := handler(logObj, req)

		//3. validate the response
		if we.env != "production" {
			err = we.validateResponse(requestValidationInput, response)
			if err != nil {
				logObj.Errorf("error validating response - %s", err)

				w.WriteHeader(http.StatusBadRequest)
				w.Write([]byte(http.StatusText(http.StatusBadRequest)))
				return
			}
		}

		//4. return response
		//4.1 headers
		if len(response.Headers) > 0 {
			for key, values := range response.Headers {
				if len(values) > 0 {
					for _, value := range values {
						w.Header().Add(key, value)
					}
				}
			}
		}
		//4.2 response code
		w.WriteHeader(response.ResponseCode)
		//4.3 body
		if len(response.Body) > 0 {
			w.Write(response.Body)
		}

		//5. print
		logObj.RequestComplete()
	}
}

func (we Adapter) validateRequest(req *http.Request) (*openapi3filter.RequestValidationInput, error) {
	route, pathParams, err := we.openAPIRouter.FindRoute(req)
	if err != nil {
		return nil, err
	}

	requestValidationInput := &openapi3filter.RequestValidationInput{
		Request:    req,
		PathParams: pathParams,
		Route:      route,
	}
	if err := openapi3filter.ValidateRequest(context.Background(), requestValidationInput); err != nil {
		return nil, err
	}
	return requestValidationInput, nil
}

func (we Adapter) validateResponse(requestValidationInput *openapi3filter.RequestValidationInput, response log.HttpResponse) error {
	responseCode := response.ResponseCode
	body := response.Body
	header := response.Headers
	options := openapi3filter.Options{IncludeResponseStatus: true}

	responseValidationInput := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: requestValidationInput,
		Status:                 responseCode,
		Header:                 header,
		Options:                &options}
	responseValidationInput.SetBodyBytes(body)

	err := openapi3filter.ValidateResponse(context.Background(), responseValidationInput)
	if err != nil {
		return err
	}
	return nil
}

//NewWebAdapter creates new WebAdapter instance
func NewWebAdapter(env string, coreAPIs *core.APIs, host string, logger *log.Logger) Adapter {
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

	auth := NewAuth(coreAPIs)
	authorization := casbin.NewEnforcer("driver/web/authorization_model.conf", "driver/web/authorization_policy.csv")

	defaultApisHandler := NewDefaultApisHandler(coreAPIs)
	servicesApisHandler := NewServicesApisHandler(coreAPIs)
	adminApisHandler := NewAdminApisHandler(coreAPIs)
	encApisHandler := NewEncApisHandler(coreAPIs)
	bbsApisHandler := NewBBsApisHandler(coreAPIs)
	return Adapter{env: env, openAPIRouter: openAPIRouter, host: host, auth: auth, logger: logger, authorization: authorization, defaultApisHandler: defaultApisHandler,
		servicesApisHandler: servicesApisHandler, adminApisHandler: adminApisHandler, encApisHandler: encApisHandler, bbsApisHandler: bbsApisHandler, coreAPIs: coreAPIs}
}

//AppListener implements core.ApplicationListener interface
type AppListener struct {
	adapter *Adapter
}
