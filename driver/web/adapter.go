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

type response struct {
	responseCode int
	header       map[string][]string
	body         []byte
}

func createErrorResponse(body string, responseCode int) response {
	headers := map[string][]string{}
	headers["Content-Type"] = []string{"text/plain; charset=utf-8"}
	headers["X-Content-Type-Options"] = []string{"nosniff"}

	return response{responseCode: responseCode, header: headers, body: []byte(body)}
}

func createSuccessResponse(body string, headers map[string]string, responseCode int) response {
	//prepare headers
	if headers == nil {
		headers = map[string]string{}
	}

	preparedHeaders := make(map[string][]string, len(headers))
	if len(headers) > 0 {
		for key, value := range headers {
			preparedHeaders[key] = []string{value}
		}
	}
	return response{responseCode: responseCode, header: preparedHeaders, body: []byte(body)}
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

type handlerFunc = func(*log.Log, http.ResponseWriter, *http.Request) response

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
		utils.LogRequest(req)
		var logObj = we.logger.NewRequestLog(req)

		//1. validate request
		requestValidationInput, err := we.validateRequest(req)
		if err != nil {
			logObj.Errorf("error validating request - %s", err)

			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(http.StatusText(http.StatusBadRequest)))
			return
		}

		//2. process it
		response := handler(logObj, w, req)

		//3. validate the response
		err = we.validateResponse(requestValidationInput, response)
		if err != nil {
			logObj.Errorf("error validating response - %s", err)

			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(http.StatusText(http.StatusBadRequest)))
			return
		}

		//4. return response
		//4.1 headers
		if len(response.header) > 0 {
			for key, values := range response.header {
				if len(values) > 0 {
					for _, value := range values {
						w.Header().Add(key, value)
					}
				}
			}
		}
		//4.2 response code
		w.WriteHeader(response.responseCode)
		//4.3 body
		if len(response.body) > 0 {
			w.Write(response.body)
		}

		//5. print
		logObj.PrintContext()
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

func (we Adapter) validateResponse(requestValidationInput *openapi3filter.RequestValidationInput, response response) error {
	responseCode := response.responseCode
	body := response.body
	header := response.header
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
