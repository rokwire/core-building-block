package web

import (
	"context"
	"core-building-block/core"
	"fmt"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	log "github.com/rokmetro/logging-library/loglib"
)

//ServicesApisHandler handles the rest APIs implementation
type ServicesApisHandler struct {
	coreAPIs *core.APIs
}

//GetAuthTest TODO get test
func (h ServicesApisHandler) GetAuthTest(l *log.Log, w http.ResponseWriter, r *http.Request) {
	res := h.coreAPIs.Services.SerGetAuthTest(l)
	w.Write([]byte(res))
}

//GetCommonTest TODO get test
func (h ServicesApisHandler) GetCommonTest(l *log.Log, w http.ResponseWriter, r *http.Request) {

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

	route, pathParams, err := router5.FindRoute(r)
	if err != nil {
		panic(err)
	}

	requestValidationInput := &openapi3filter.RequestValidationInput{
		Request:    r,
		PathParams: pathParams,
		Route:      route,
	}
	if err := openapi3filter.ValidateRequest(ctx, requestValidationInput); err != nil {
		panic(err)
	}

	responseValidationInput := &openapi3filter.ResponseValidationInput{
		RequestValidationInput: requestValidationInput,
		Status:                 200,
		Header:                 http.Header{"Content-Type": []string{"application/json"}},
	}
	responseValidationInput.SetBodyBytes([]byte(`{}`))

	err = openapi3filter.ValidateResponse(ctx, responseValidationInput)
	fmt.Println(err)

	///

	res := h.coreAPIs.Services.SerGetCommonTest(l)
	w.Write([]byte(res))
}

//SerVersion gives the service version
func (h ServicesApisHandler) SerVersion(l *log.Log, w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(h.coreAPIs.Services.SerGetVersion(l)))
}

//NewServicesApisHandler creates new rest services Handler instance
func NewServicesApisHandler(coreAPIs *core.APIs) ServicesApisHandler {
	return ServicesApisHandler{coreAPIs: coreAPIs}
}
