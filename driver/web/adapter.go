package web

import (
	"context"
	"core-building-block/core"
	"fmt"
	"html/template"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/rokwire/logging-library-go/errors"
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
	systemApisHandler   SystemApisHandler

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

	//docs
	subRouter.PathPrefix("/doc/ui").Handler(we.serveDocUI()) //Public
	subRouter.HandleFunc("/doc", we.serveDoc)                //Public
	///

	//ui
	subRouter.HandleFunc("/ui/credential/reset", we.serveResetCredential)                                                     //Public
	subRouter.HandleFunc("/ui/credential/verify", we.uiWrapFunc(we.servicesApisHandler.verifyCredential, nil)).Methods("GET") //Public (validates code)

	///default ///
	subRouter.HandleFunc("/version", we.wrapFunc(we.defaultApisHandler.getVersion, nil)).Methods("GET")                                      //Public
	subRouter.HandleFunc("/.well-known/openid-configuration", we.wrapFunc(we.defaultApisHandler.getOpenIDConfiguration, nil)).Methods("GET") //Public
	///

	///services ///
	servicesSubRouter := subRouter.PathPrefix("/services").Subrouter()
	servicesSubRouter.HandleFunc("/auth/login", we.wrapFunc(we.servicesApisHandler.authLogin, nil)).Methods("POST")        //Requires API key in request
	servicesSubRouter.HandleFunc("/auth/mfa", we.wrapFunc(we.servicesApisHandler.authLoginMFA, nil)).Methods("POST")       //Requires API key in request
	servicesSubRouter.HandleFunc("/auth/login-url", we.wrapFunc(we.servicesApisHandler.authLoginURL, nil)).Methods("POST") //Requires API key in request
	servicesSubRouter.HandleFunc("/auth/refresh", we.wrapFunc(we.servicesApisHandler.authRefresh, nil)).Methods("POST")    //Requires API key in request
	servicesSubRouter.HandleFunc("/auth/logout", we.wrapFunc(we.servicesApisHandler.authLogout, we.auth.services.user)).Methods("POST")
	servicesSubRouter.HandleFunc("/auth/account/exists", we.wrapFunc(we.servicesApisHandler.accountExists, nil)).Methods("POST")  //Requires API key in request
	servicesSubRouter.HandleFunc("/auth/account/can-sign-in", we.wrapFunc(we.servicesApisHandler.canSignIn, nil)).Methods("POST") //Requires API key in request
	servicesSubRouter.HandleFunc("/auth/account/can-link", we.wrapFunc(we.servicesApisHandler.canLink, nil)).Methods("POST")      //Requires API key in request
	servicesSubRouter.HandleFunc("/auth/account/auth-type/link", we.wrapFunc(we.servicesApisHandler.linkAccountAuthType, we.auth.services.authenticated)).Methods("POST")
	servicesSubRouter.HandleFunc("/auth/account/auth-type/link", we.wrapFunc(we.servicesApisHandler.unlinkAccountAuthType, we.auth.services.authenticated)).Methods("DELETE")
	servicesSubRouter.HandleFunc("/auth/credential/verify", we.wrapFunc(we.servicesApisHandler.verifyCredential, nil)).Methods("GET")                   //Public (validates code)
	servicesSubRouter.HandleFunc("/auth/credential/send-verify", we.wrapFunc(we.servicesApisHandler.sendVerifyCredential, nil)).Methods("POST")         //Requires API key in request
	servicesSubRouter.HandleFunc("/auth/credential/forgot/initiate", we.wrapFunc(we.servicesApisHandler.forgotCredentialInitiate, nil)).Methods("POST") //Requires API key in request
	servicesSubRouter.HandleFunc("/auth/credential/forgot/complete", we.wrapFunc(we.servicesApisHandler.forgotCredentialComplete, nil)).Methods("POST") //Public
	servicesSubRouter.HandleFunc("/auth/credential/update", we.wrapFunc(we.servicesApisHandler.updateCredential, we.auth.services.authenticated)).Methods("POST")
	servicesSubRouter.HandleFunc("/auth/verify-mfa", we.wrapFunc(we.servicesApisHandler.verifyMFA, we.auth.services.user)).Methods("POST")
	servicesSubRouter.HandleFunc("/auth/authorize-service", we.wrapFunc(we.servicesApisHandler.authAuthorizeService, we.auth.services.user)).Methods("POST")
	servicesSubRouter.HandleFunc("/auth/service-regs", we.wrapFunc(we.servicesApisHandler.getServiceRegistrations, we.auth.services.user)).Methods("GET")
	servicesSubRouter.HandleFunc("/account", we.wrapFunc(we.servicesApisHandler.deleteAccount, we.auth.services.user)).Methods("DELETE")
	servicesSubRouter.HandleFunc("/account", we.wrapFunc(we.servicesApisHandler.getAccount, we.auth.services.user)).Methods("GET")
	servicesSubRouter.HandleFunc("/account/mfa", we.wrapFunc(we.servicesApisHandler.getMFATypes, we.auth.services.user)).Methods("GET")
	servicesSubRouter.HandleFunc("/account/mfa", we.wrapFunc(we.servicesApisHandler.addMFAType, we.auth.services.authenticated)).Methods("POST")
	servicesSubRouter.HandleFunc("/account/mfa", we.wrapFunc(we.servicesApisHandler.removeMFAType, we.auth.services.authenticated)).Methods("DELETE")
	servicesSubRouter.HandleFunc("/account/preferences", we.wrapFunc(we.servicesApisHandler.updateAccountPreferences, we.auth.services.user)).Methods("PUT")
	servicesSubRouter.HandleFunc("/account/preferences", we.wrapFunc(we.servicesApisHandler.getPreferences, we.auth.services.user)).Methods("GET")
	servicesSubRouter.HandleFunc("/account/profile", we.wrapFunc(we.servicesApisHandler.getProfile, we.auth.services.user)).Methods("GET")
	servicesSubRouter.HandleFunc("/account/profile", we.wrapFunc(we.servicesApisHandler.updateProfile, we.auth.services.user)).Methods("PUT")
	servicesSubRouter.HandleFunc("/test", we.wrapFunc(we.servicesApisHandler.getTest, nil)).Methods("GET")                               //Public
	servicesSubRouter.HandleFunc("/application/configs", we.wrapFunc(we.servicesApisHandler.getApplicationConfigs, nil)).Methods("POST") //Requires API key in request
	servicesSubRouter.HandleFunc("/application/organization/configs", we.wrapFunc(we.servicesApisHandler.getApplicationOrgConfigs, we.auth.services.standard)).Methods("POST")
	///

	///admin ///
	adminSubrouter := subRouter.PathPrefix("/admin").Subrouter()
	adminSubrouter.HandleFunc("/test", we.wrapFunc(we.adminApisHandler.getTest, we.auth.admin.permissions)).Methods("GET")
	adminSubrouter.HandleFunc("/test-model", we.wrapFunc(we.adminApisHandler.getTestModel, we.auth.admin.permissions)).Methods("GET")

	adminSubrouter.HandleFunc("/auth/login", we.wrapFunc(we.adminApisHandler.adminLogin, nil)).Methods("POST")
	adminSubrouter.HandleFunc("/auth/mfa", we.wrapFunc(we.adminApisHandler.adminLoginMFA, nil)).Methods("POST")
	adminSubrouter.HandleFunc("/auth/login-url", we.wrapFunc(we.adminApisHandler.adminLoginURL, nil)).Methods("POST")
	adminSubrouter.HandleFunc("/auth/refresh", we.wrapFunc(we.adminApisHandler.adminRefresh, nil)).Methods("POST")
	adminSubrouter.HandleFunc("/auth/verify-mfa", we.wrapFunc(we.adminApisHandler.adminVerifyMFA, we.auth.admin.user)).Methods("POST")
	adminSubrouter.HandleFunc("/auth/app-token", we.wrapFunc(we.adminApisHandler.getAppToken, we.auth.admin.user)).Methods("GET")

	adminSubrouter.HandleFunc("/account", we.wrapFunc(we.adminApisHandler.getAccount, we.auth.admin.user)).Methods("GET")
	adminSubrouter.HandleFunc("/account/mfa", we.wrapFunc(we.adminApisHandler.getMFATypes, we.auth.admin.user)).Methods("GET")
	adminSubrouter.HandleFunc("/account/mfa", we.wrapFunc(we.adminApisHandler.addMFAType, we.auth.admin.authenticated)).Methods("POST")
	adminSubrouter.HandleFunc("/account/mfa", we.wrapFunc(we.adminApisHandler.removeMFAType, we.auth.admin.authenticated)).Methods("DELETE")

	adminSubrouter.HandleFunc("/organization/applications", we.wrapFunc(we.adminApisHandler.adminGetApplications, we.auth.admin.user)).Methods("GET")

	adminSubrouter.HandleFunc("/application/login-sessions", we.wrapFunc(we.adminApisHandler.getApplicationLoginSessions, we.auth.admin.permissions)).Methods("GET")

	adminSubrouter.HandleFunc("/application/groups", we.wrapFunc(we.adminApisHandler.adminGetApplicationGroups, we.auth.admin.permissions)).Methods("GET")
	adminSubrouter.HandleFunc("/application/groups", we.wrapFunc(we.adminApisHandler.adminCreateApplicationGroup, we.auth.admin.permissions)).Methods("POST")
	adminSubrouter.HandleFunc("/application/groups/{id}", we.wrapFunc(we.adminApisHandler.adminDeleteApplicationGroup, we.auth.admin.permissions)).Methods("DELETE")

	adminSubrouter.HandleFunc("/application/roles", we.wrapFunc(we.adminApisHandler.adminGetApplicationOrgRoles, we.auth.admin.permissions)).Methods("GET")
	adminSubrouter.HandleFunc("/application/roles", we.wrapFunc(we.adminApisHandler.adminCreateApplicationRole, we.auth.admin.permissions)).Methods("POST")
	adminSubrouter.HandleFunc("/application/roles/{id}", we.wrapFunc(we.adminApisHandler.adminDeleteApplicationRole, we.auth.admin.permissions)).Methods("DELETE")

	adminSubrouter.HandleFunc("/application/permissions", we.wrapFunc(we.adminApisHandler.getApplicationPermissions, we.auth.admin.permissions)).Methods("GET")

	adminSubrouter.HandleFunc("/application/accounts", we.wrapFunc(we.adminApisHandler.getApplicationAccounts, we.auth.admin.permissions)).Methods("GET")

	adminSubrouter.HandleFunc("/application/account/{account_id}/login-sessions/{session_id}", we.wrapFunc(we.adminApisHandler.deleteApplicationLoginSession, we.auth.admin.permissions)).Methods("DELETE")
	adminSubrouter.HandleFunc("/application/account/{id}/devices", we.wrapFunc(we.adminApisHandler.getApplicationAccountDevices, we.auth.admin.permissions)).Methods("GET")
	adminSubrouter.HandleFunc("/application/account/permissions/grant", we.wrapFunc(we.adminApisHandler.grantAccountPermissions, we.auth.admin.permissions)).Methods("PUT")
	adminSubrouter.HandleFunc("/application/account/roles/grant", we.wrapFunc(we.adminApisHandler.grantAccountRoles, we.auth.admin.user)).Methods("PUT")
	///

	///enc ///
	encSubrouter := subRouter.PathPrefix("/enc").Subrouter()
	encSubrouter.HandleFunc("/test", we.wrapFunc(we.encApisHandler.getTest, nil)).Methods("GET") //Public
	///

	///bbs ///
	bbsSubrouter := subRouter.PathPrefix("/bbs").Subrouter()
	bbsSubrouter.HandleFunc("/service-regs", we.wrapFunc(we.bbsApisHandler.getServiceRegistrations, nil)).Methods("GET") //Public
	bbsSubrouter.HandleFunc("/test", we.wrapFunc(we.bbsApisHandler.getTest, nil)).Methods("GET")                         //Public
	///

	///third-party services ///
	tpsSubrouter := subRouter.PathPrefix("/tps").Subrouter()
	tpsSubrouter.HandleFunc("/service-regs", we.wrapFunc(we.tpsApisHandler.getServiceRegistrations, nil)).Methods("GET") //Public
	tpsSubrouter.HandleFunc("/auth-keys", we.wrapFunc(we.tpsApisHandler.getAuthKeys, nil)).Methods("GET")                //Public
	///

	///system ///
	//TODO - disable until we implement the system accounts login so that to protect them
	/*
		systemSubrouter := subRouter.PathPrefix("/system").Subrouter()
		systemSubrouter.HandleFunc("/global-config", we.wrapFunc(we.systemApisHandler.createGlobalConfig, we.auth.systemAuth)).Methods("POST")
		systemSubrouter.HandleFunc("/global-config", we.wrapFunc(we.systemApisHandler.getGlobalConfig, we.auth.systemAuth)).Methods("GET")
		systemSubrouter.HandleFunc("/global-config", we.wrapFunc(we.systemApisHandler.updateGlobalConfig, we.auth.systemAuth)).Methods("PUT")

		systemSubrouter.HandleFunc("/organizations", we.wrapFunc(we.systemApisHandler.createOrganization, we.auth.systemAuth)).Methods("POST")
		systemSubrouter.HandleFunc("/organizations/{id}", we.wrapFunc(we.systemApisHandler.updateOrganization, we.auth.systemAuth)).Methods("PUT")
		systemSubrouter.HandleFunc("/organizations/{id}", we.wrapFunc(we.systemApisHandler.getOrganization, we.auth.systemAuth)).Methods("GET")
		systemSubrouter.HandleFunc("/organizations", we.wrapFunc(we.systemApisHandler.getOrganizations, we.auth.systemAuth)).Methods("GET")

		systemSubrouter.HandleFunc("/applications", we.wrapFunc(we.systemApisHandler.createApplication, we.auth.systemAuth)).Methods("POST")
		systemSubrouter.HandleFunc("/applications/{id}", we.wrapFunc(we.systemApisHandler.getApplication, we.auth.systemAuth)).Methods("GET")
		systemSubrouter.HandleFunc("/applications", we.wrapFunc(we.systemApisHandler.getApplications, we.auth.systemAuth)).Methods("GET")

		systemSubrouter.HandleFunc("/permissions", we.wrapFunc(we.systemApisHandler.createPermission, we.auth.systemAuth)).Methods("POST")
		systemSubrouter.HandleFunc("/permissions", we.wrapFunc(we.systemApisHandler.updatePermission, we.auth.systemAuth)).Methods("PUT")
		systemSubrouter.HandleFunc("/application-roles", we.wrapFunc(we.systemApisHandler.createApplicationRole, we.auth.systemAuth)).Methods("POST")
		systemSubrouter.HandleFunc("/application-api-keys", we.wrapFunc(we.systemApisHandler.getApplicationAPIKeys, we.auth.systemAuth)).Methods("GET")

		systemSubrouter.HandleFunc("/application/configs", we.wrapFunc(we.systemApisHandler.getApplicationConfigs, we.auth.systemAuth)).Methods("GET")
		systemSubrouter.HandleFunc("/application/configs", we.wrapFunc(we.systemApisHandler.createApplicationConfig, we.auth.systemAuth)).Methods("POST")
		systemSubrouter.HandleFunc("/application/configs/{id}", we.wrapFunc(we.systemApisHandler.getApplicationConfig, we.auth.systemAuth)).Methods("GET")
		systemSubrouter.HandleFunc("/application/configs/{id}", we.wrapFunc(we.systemApisHandler.updateApplicationConfig, we.auth.systemAuth)).Methods("PUT")
		systemSubrouter.HandleFunc("/application/configs/{id}", we.wrapFunc(we.systemApisHandler.deleteApplicationConfig, we.auth.systemAuth)).Methods("DELETE")

		systemSubrouter.HandleFunc("/account/permissions", we.wrapFunc(we.systemApisHandler.grantAccountPermissions, we.auth.systemAuth)).Methods("PUT")
		systemSubrouter.HandleFunc("/account/roles", we.wrapFunc(we.systemApisHandler.grantAccountRoles, we.auth.systemAuth)).Methods("PUT")
		// systemSubrouter.HandleFunc("/account/mfa", we.wrapFunc(we.systemApisHandler.getMFATypes, we.auth.servicesUserAuth)).Methods("GET")
		// systemSubrouter.HandleFunc("/account/mfa", we.wrapFunc(we.systemApisHandler.addMFAType, we.auth.servicesAuthenticatedAuth)).Methods("POST")
		// systemSubrouter.HandleFunc("/account/mfa", we.wrapFunc(we.systemApisHandler.removeMFAType, we.auth.servicesAuthenticatedAuth)).Methods("DELETE")

		systemSubrouter.HandleFunc("/service-regs", we.wrapFunc(we.systemApisHandler.getServiceRegistrations, we.auth.systemAuth)).Methods("GET")
		systemSubrouter.HandleFunc("/service-regs", we.wrapFunc(we.systemApisHandler.registerService, we.auth.systemAuth)).Methods("POST")
		systemSubrouter.HandleFunc("/service-regs", we.wrapFunc(we.systemApisHandler.updateServiceRegistration, we.auth.systemAuth)).Methods("PUT")
		systemSubrouter.HandleFunc("/service-regs", we.wrapFunc(we.systemApisHandler.deregisterService, we.auth.systemAuth)).Methods("DELETE")

		systemSubrouter.HandleFunc("/api-keys", we.wrapFunc(we.systemApisHandler.getAPIKey, we.auth.systemAuth)).Methods("GET")
		systemSubrouter.HandleFunc("/api-keys", we.wrapFunc(we.systemApisHandler.createAPIKey, we.auth.systemAuth)).Methods("POST")
		systemSubrouter.HandleFunc("/api-keys", we.wrapFunc(we.systemApisHandler.updateAPIKey, we.auth.systemAuth)).Methods("PUT")
		systemSubrouter.HandleFunc("/api-keys", we.wrapFunc(we.systemApisHandler.deleteAPIKey, we.auth.systemAuth)).Methods("DELETE")
		systemSubrouter.HandleFunc("/auth-types", we.wrapFunc(we.systemApisHandler.createAuthTypes, we.auth.systemAuth)).Methods("POST")
		systemSubrouter.HandleFunc("/auth-types", we.wrapFunc(we.systemApisHandler.getAuthTypes, we.auth.systemAuth)).Methods("GET")
		systemSubrouter.HandleFunc("/auth-types/{id}", we.wrapFunc(we.systemApisHandler.updateAuthTypes, we.auth.systemAuth)).Methods("PUT")
	*/
	///

	err := http.ListenAndServe(":"+we.port, router)
	if err != nil {
		we.logger.Fatalf("error on listen and server - %s", err.Error())
	}
}

func (we Adapter) serveResetCredential(w http.ResponseWriter, r *http.Request) {
	fmt.Println(r.URL.Path)
	w.Header().Add("access-control-allow-origin", "*")
	http.ServeFile(w, r, "./driver/web/ui/reset-credential.html")
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

		var err error

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
				logObj.RequestErrorAction(w, logutils.ActionValidate, logutils.TypeResponse, &logutils.FieldArgs{"code": response.ResponseCode, "headers": response.Headers, "body": string(response.Body)}, err, http.StatusInternalServerError, true)
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

func (we Adapter) uiWrapFunc(handler handlerFunc, authorization Authorization) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		logObj := we.logger.NewRequestLog(req)

		logObj.RequestReceived()

		//1. validate request
		_, err := we.validateRequest(req)
		if err != nil {
			message := errors.WrapErrorAction(logutils.ActionValidate, logutils.TypeRequest, nil, err)
			we.serveResponseUI(w, message.Error(), true, logObj)
			return
		}

		//2. process it
		var response logs.HttpResponse
		if authorization != nil {
			_, claims, err := authorization.check(req)
			if err != nil {
				message := errors.WrapErrorAction(logutils.ActionValidate, logutils.TypeRequest, nil, err)
				we.serveResponseUI(w, message.Error(), true, logObj)
				return
			}
			response = handler(logObj, req, claims)
		} else {
			response = handler(logObj, req, nil)
		}

		we.serveResponseUI(w, string(response.Body), response.ResponseCode != 200, logObj)
		//5. print
		logObj.RequestComplete()
	}
}

func (we Adapter) serveResponseUI(w http.ResponseWriter, message string, isErr bool, l *logs.Log) {
	file := ""
	if isErr {
		file = "./driver/web/ui/error.html"
		l.Error(message)
	} else {
		file = "./driver/web/ui/success.html"
	}
	tmpl, err := template.ParseFiles(file)
	if err != nil {
		l.RequestErrorAction(w, logutils.ActionLoad, "page template", nil, err, http.StatusInternalServerError, true)
	}
	data := HTMLResponseTemplate{Message: message}
	// w.Header().Add("access-control-allow-origin", "*")
	tmpl.Execute(w, data)
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
	systemApisHandler := NewSystemApisHandler(coreAPIs)
	return Adapter{env: env, port: port, openAPIRouter: openAPIRouter, host: host, auth: auth, logger: logger, defaultApisHandler: defaultApisHandler, servicesApisHandler: servicesApisHandler, adminApisHandler: adminApisHandler,
		encApisHandler: encApisHandler, bbsApisHandler: bbsApisHandler, tpsApisHandler: tpsApisHandler, systemApisHandler: systemApisHandler, coreAPIs: coreAPIs}
}

//AppListener implements core.ApplicationListener interface
type AppListener struct {
	adapter *Adapter
}
