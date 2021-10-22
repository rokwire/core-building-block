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
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"

	"github.com/gorilla/mux"

	"github.com/rokwire/core-auth-library-go/authservice"
	"github.com/rokwire/core-auth-library-go/tokenauth"

	httpSwagger "github.com/swaggo/http-swagger"
)

//Adapter entity
type Adapter struct {
	env       string
	serviceID string
	port      string

	openAPIRouter routers.Router
	host          string
	auth          *Auth
	// authorization *casbin.Enforcer
	logger *logs.Logger

	defaultApisHandler  DefaultApisHandler
	servicesApisHandler ServicesApisHandler
	adminApisHandler    AdminApisHandler
	encApisHandler      EncApisHandler
	bbsApisHandler      BBsApisHandler
	tpsApisHandler      TPSApisHandler

	coreAPIs *core.APIs
}

type handlerFunc = func(*logs.Log, *http.Request, *tokenauth.Claims) logs.HttpResponse

//Start starts the module
func (we Adapter) Start() {

	//add listener to the application
	we.coreAPIs.AddListener(&AppListener{&we})

	we.auth.Start()

	router := mux.NewRouter().StrictSlash(true)
	subRouter := router.PathPrefix("/core").Subrouter()

	// handle apis
	subRouter.PathPrefix("/doc/ui").Handler(we.serveDocUI())
	subRouter.HandleFunc("/doc", we.serveDoc)

	///default ///
	subRouter.HandleFunc("/version", we.wrapFunc(we.defaultApisHandler.getVersion, nil)).Methods("GET")
	subRouter.HandleFunc("/.well-known/openid-configuration", we.wrapFunc(we.defaultApisHandler.getOpenIDConfiguration, nil)).Methods("GET")
	///

	///services ///
	servicesSubRouter := subRouter.PathPrefix("/services").Subrouter()
	servicesSubRouter.HandleFunc("/auth/login", we.wrapFunc(we.servicesApisHandler.authLogin, nil)).Methods("POST")
	servicesSubRouter.HandleFunc("/auth/login-url", we.wrapFunc(we.servicesApisHandler.authLoginURL, nil)).Methods("POST")
	servicesSubRouter.HandleFunc("/auth/refresh", we.wrapFunc(we.servicesApisHandler.authRefresh, nil)).Methods("POST")
	servicesSubRouter.HandleFunc("/auth/verify", we.wrapFunc(we.servicesApisHandler.verifyCode, nil)).Methods("GET")
	servicesSubRouter.HandleFunc("/auth/authorize-service", we.wrapFunc(we.servicesApisHandler.authAuthorizeService, we.auth.servicesUserAuth)).Methods("POST")
	servicesSubRouter.HandleFunc("/auth/service-regs", we.wrapFunc(we.servicesApisHandler.getServiceRegistrations, we.auth.servicesAuth)).Methods("GET")
	servicesSubRouter.HandleFunc("/account", we.wrapFunc(we.servicesApisHandler.deleteAccount, we.auth.servicesUserAuth)).Methods("DELETE")
	servicesSubRouter.HandleFunc("/account/preferences", we.wrapFunc(we.servicesApisHandler.updateAccountPreferences, we.auth.servicesUserAuth)).Methods("PUT")
	servicesSubRouter.HandleFunc("/account/preferences", we.wrapFunc(we.servicesApisHandler.getPreferences, we.auth.servicesUserAuth)).Methods("GET")
	servicesSubRouter.HandleFunc("/account/profile", we.wrapFunc(we.servicesApisHandler.getProfile, we.auth.servicesUserAuth)).Methods("GET")
	servicesSubRouter.HandleFunc("/account/profile", we.wrapFunc(we.servicesApisHandler.updateProfile, we.auth.servicesUserAuth)).Methods("PUT")
	servicesSubRouter.HandleFunc("/test", we.wrapFunc(we.servicesApisHandler.getTest, nil)).Methods("GET")
	///

	///admin ///
	adminSubrouter := subRouter.PathPrefix("/admin").Subrouter()
	adminSubrouter.HandleFunc("/test", we.wrapFunc(we.adminApisHandler.getTest, we.auth.adminAuth)).Methods("GET")
	adminSubrouter.HandleFunc("/test-model", we.wrapFunc(we.adminApisHandler.getTestModel, we.auth.adminAuth)).Methods("GET")

	adminSubrouter.HandleFunc("/global-config", we.wrapFunc(we.adminApisHandler.createGlobalConfig, we.auth.adminAuth)).Methods("POST")
	adminSubrouter.HandleFunc("/global-config", we.wrapFunc(we.adminApisHandler.getGlobalConfig, we.auth.adminAuth)).Methods("GET")
	adminSubrouter.HandleFunc("/global-config", we.wrapFunc(we.adminApisHandler.updateGlobalConfig, we.auth.adminAuth)).Methods("PUT")

	adminSubrouter.HandleFunc("/organizations", we.wrapFunc(we.adminApisHandler.createOrganization, we.auth.adminAuth)).Methods("POST")
	adminSubrouter.HandleFunc("/organizations/{id}", we.wrapFunc(we.adminApisHandler.updateOrganization, we.auth.adminAuth)).Methods("PUT")
	adminSubrouter.HandleFunc("/organizations/{id}", we.wrapFunc(we.adminApisHandler.getOrganization, we.auth.adminAuth)).Methods("GET")
	adminSubrouter.HandleFunc("/organizations", we.wrapFunc(we.adminApisHandler.getOrganizations, we.auth.adminAuth)).Methods("GET")

	adminSubrouter.HandleFunc("/applications", we.wrapFunc(we.adminApisHandler.createApplication, we.auth.adminAuth)).Methods("POST")
	adminSubrouter.HandleFunc("/applications/{id}", we.wrapFunc(we.adminApisHandler.getApplication, we.auth.adminAuth)).Methods("GET")
	adminSubrouter.HandleFunc("/applications", we.wrapFunc(we.adminApisHandler.getApplications, we.auth.adminAuth)).Methods("GET")

	adminSubrouter.HandleFunc("/application-permissions", we.wrapFunc(we.adminApisHandler.createApplicationPermission, we.auth.adminAuth)).Methods("POST")
	adminSubrouter.HandleFunc("/application-roles", we.wrapFunc(we.adminApisHandler.createApplicationRole, we.auth.adminAuth)).Methods("POST")

	adminSubrouter.HandleFunc("/account/permissions", we.wrapFunc(we.adminApisHandler.grantAccountPermissions, we.auth.adminAuth)).Methods("PUT")
	adminSubrouter.HandleFunc("/account/roles", we.wrapFunc(we.adminApisHandler.grantAccountRoles, we.auth.adminAuth)).Methods("PUT")

	adminSubrouter.HandleFunc("/service-regs", we.wrapFunc(we.adminApisHandler.getServiceRegistrations, we.auth.adminAuth)).Methods("GET")
	adminSubrouter.HandleFunc("/service-regs", we.wrapFunc(we.adminApisHandler.registerService, we.auth.adminAuth)).Methods("POST")
	adminSubrouter.HandleFunc("/service-regs", we.wrapFunc(we.adminApisHandler.updateServiceRegistration, we.auth.adminAuth)).Methods("PUT")
	adminSubrouter.HandleFunc("/service-regs", we.wrapFunc(we.adminApisHandler.deregisterService, we.auth.adminAuth)).Methods("DELETE")

	adminSubrouter.HandleFunc("/api-keys", we.wrapFunc(we.adminApisHandler.getAPIKey, we.auth.adminAuth)).Methods("GET")
	adminSubrouter.HandleFunc("/api-keys", we.wrapFunc(we.adminApisHandler.createAPIKey, we.auth.adminAuth)).Methods("POST")
	adminSubrouter.HandleFunc("/api-keys", we.wrapFunc(we.adminApisHandler.updateAPIKey, we.auth.adminAuth)).Methods("PUT")
	adminSubrouter.HandleFunc("/api-keys", we.wrapFunc(we.adminApisHandler.deleteAPIKey, we.auth.adminAuth)).Methods("DELETE")

	adminSubrouter.HandleFunc("/login-url", we.wrapFunc(we.adminApisHandler.adminLoginURL, nil)).Methods("POST")
	///

	///enc ///
	encSubrouter := subRouter.PathPrefix("/enc").Subrouter()
	encSubrouter.HandleFunc("/test", we.wrapFunc(we.encApisHandler.getTest, nil)).Methods("GET")
	///

	///bbs ///
	bbsSubrouter := subRouter.PathPrefix("/bbs").Subrouter()
	bbsSubrouter.HandleFunc("/test", we.wrapFunc(we.bbsApisHandler.getTest, nil)).Methods("GET")
	bbsSubrouter.HandleFunc("/service-regs", we.wrapFunc(we.bbsApisHandler.getServiceRegistrations, nil)).Methods("GET")
	///

	///third-party services ///
	tpsSubrouter := subRouter.PathPrefix("/tps").Subrouter()
	tpsSubrouter.HandleFunc("/service-regs", we.wrapFunc(we.tpsApisHandler.getServiceRegistrations, nil)).Methods("GET")
	tpsSubrouter.HandleFunc("/auth-keys", we.wrapFunc(we.tpsApisHandler.getAuthKeys, nil)).Methods("GET")
	///

	err := http.ListenAndServe(":"+we.port, router)
	if err != nil {
		we.logger.Fatalf("error on listen and server - %s", err.Error())
	}
}

func (we Adapter) serveDoc(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("access-control-allow-origin", "*")
	http.ServeFile(w, r, "./driver/web/docs/gen/def.yaml")
}

func (we Adapter) serveDocUI() http.Handler {
	url := fmt.Sprintf("%s/doc", we.host)
	return httpSwagger.Handler(httpSwagger.URL(url))
}

func (we Adapter) wrapFunc(handler handlerFunc, authorization Authorization) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		logObj := we.logger.NewRequestLog(req)

		logObj.RequestReceived()

		//var err error

		//1. validate request
		requestValidationInput, err := we.validateRequest(req)
		if err != nil {
			logObj.RequestErrorAction(w, logutils.ActionValidate, logutils.TypeRequest, nil, err, http.StatusBadRequest, true)
			return
		}

		//2. process it
		var response logs.HttpResponse
		if authorization != nil {
			responseStatus, claims, err := authorization.check(req)
			if err != nil {
				logObj.RequestErrorAction(w, logutils.ActionValidate, logutils.TypeRequest, nil, err, responseStatus, true)
				return
			}
			response = handler(logObj, req, claims)
		} else {
			response = handler(logObj, req, nil)
		}

		//3. validate the response
		if we.env != "production" {
			err = we.validateResponse(requestValidationInput, response)
			if err != nil {
				logObj.RequestErrorAction(w, logutils.ActionValidate, logutils.TypeResponse, nil, err, http.StatusInternalServerError, true)
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

	dummyAuthFunc := func(c context.Context, input *openapi3filter.AuthenticationInput) error {
		return nil
	}
	options := &openapi3filter.Options{AuthenticationFunc: dummyAuthFunc}
	requestValidationInput := &openapi3filter.RequestValidationInput{
		Request:    req,
		PathParams: pathParams,
		Route:      route,
		Options:    options,
	}

	if err := openapi3filter.ValidateRequest(context.Background(), requestValidationInput); err != nil {
		return nil, err
	}
	return requestValidationInput, nil
}

func (we Adapter) validateResponse(requestValidationInput *openapi3filter.RequestValidationInput, response logs.HttpResponse) error {
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
func NewWebAdapter(env string, serviceID string, authService *authservice.AuthService, port string, coreAPIs *core.APIs, host string, logger *logs.Logger) Adapter {
	//openAPI doc
	loader := &openapi3.Loader{Context: context.Background(), IsExternalRefsAllowed: true}
	doc, err := loader.LoadFromFile("driver/web/docs/gen/def.yaml")
	if err != nil {
		logger.Fatalf("error on openapi3 load from file - %s", err.Error())
	}
	err = doc.Validate(loader.Context)
	if err != nil {
		logger.Fatalf("error on openapi3 validate - %s", err.Error())
	}

	//Ignore servers. Validating reqeusts against the documented servers can cause issues when routing traffic through proxies/load-balancers.
	doc.Servers = nil

	//To correctly route traffic to base path, we must add to all paths since servers are ignored
	paths := make(openapi3.Paths, len(doc.Paths))
	for path, obj := range doc.Paths {
		paths["/core"+path] = obj
	}
	doc.Paths = paths

	openAPIRouter, err := gorillamux.NewRouter(doc)
	if err != nil {
		logger.Fatalf("error on openapi3 gorillamux router - %s", err.Error())
	}

	auth, err := NewAuth(coreAPIs, serviceID, authService, logger)
	if err != nil {
		logger.Fatal(err.Error())
	}

	defaultApisHandler := NewDefaultApisHandler(coreAPIs)
	servicesApisHandler := NewServicesApisHandler(coreAPIs)
	adminApisHandler := NewAdminApisHandler(coreAPIs)
	encApisHandler := NewEncApisHandler(coreAPIs)
	bbsApisHandler := NewBBsApisHandler(coreAPIs)
	tpsApisHandler := NewTPSApisHandler(coreAPIs)
	return Adapter{env: env, port: port, openAPIRouter: openAPIRouter, host: host, auth: auth, logger: logger, defaultApisHandler: defaultApisHandler, servicesApisHandler: servicesApisHandler, adminApisHandler: adminApisHandler,
		encApisHandler: encApisHandler, bbsApisHandler: bbsApisHandler, tpsApisHandler: tpsApisHandler, coreAPIs: coreAPIs}
}

//AppListener implements core.ApplicationListener interface
type AppListener struct {
	adapter *Adapter
}
