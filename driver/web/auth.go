// Copyright 2022 Board of Trustees of the University of Illinois.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package web

import (
	"net/http"

	"github.com/rokwire/core-auth-library-go/v2/authorization"
	"github.com/rokwire/core-auth-library-go/v2/authservice"
	"github.com/rokwire/core-auth-library-go/v2/tokenauth"
	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

const (
	typeCheckScope                    logutils.MessageActionType = "checking scope"
	typeCheckSystemAuthRequestToken   logutils.MessageActionType = "checking system auth"
	typeCheckTPsAuthRequestToken      logutils.MessageActionType = "checking tps auth"
	typeCheckBBsAuthRequestToken      logutils.MessageActionType = "checking bbs auth"
	typeCheckAdminAuthRequestToken    logutils.MessageActionType = "checking admin auth"
	typeCheckServicesAuthRequestToken logutils.MessageActionType = "checking services auth"
)

// Auth handler
type Auth struct {
	services *tokenauth.Handlers
	admin    *tokenauth.Handlers
	encAuth  *tokenauth.Handlers
	bbs      *tokenauth.Handlers
	tps      *tokenauth.Handlers
	system   *tokenauth.Handlers
}

// NewAuth creates new auth handler
func NewAuth(serviceID string, serviceRegManager *authservice.ServiceRegManager) (*Auth, error) {
	servicesAuth, err := newServicesAuth(serviceRegManager, serviceID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, "services auth", nil, err)
	}
	serviceHandlers := tokenauth.NewHandlers(servicesAuth)

	adminAuth, err := newAdminAuth(serviceRegManager)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "admin auth", nil, err)
	}
	adminHandlers := tokenauth.NewHandlers(adminAuth)

	encAuth, err := newEncAuth(serviceRegManager)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, "enc auth", nil, err)
	}
	encHandlers := tokenauth.NewHandlers(encAuth)

	bbsAuth, err := newBBsAuth(serviceRegManager)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "bbs auth", nil, err)
	}
	bbsHandlers := tokenauth.NewHandlers(bbsAuth)

	tpsAuth, err := newTPsAuth(serviceRegManager)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "tps auth", nil, err)
	}
	tpsHandlers := tokenauth.NewHandlers(tpsAuth)

	systemAuth, err := newSystemAuth(serviceRegManager)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "auth handler", nil, err)
	}
	systemHandlers := tokenauth.NewHandlers(systemAuth)

	auth := Auth{services: &serviceHandlers, admin: &adminHandlers, encAuth: &encHandlers, bbs: &bbsHandlers, tps: &tpsHandlers, system: &systemHandlers}

	return &auth, nil
}

// ServicesAuth entity
type ServicesAuth struct {
	tokenAuth *tokenauth.TokenAuth
}

// Check checks the token in the provided request
func (auth *ServicesAuth) Check(req *http.Request) (int, *tokenauth.Claims, error) {
	claims, err := auth.tokenAuth.CheckRequestTokens(req)
	if err != nil {
		return http.StatusUnauthorized, nil, errors.WrapErrorAction(typeCheckServicesAuthRequestToken, logutils.TypeToken, nil, err)
	}

	if claims.Admin {
		return http.StatusUnauthorized, nil, errors.ErrorData(logutils.StatusInvalid, "admin claim", nil)
	}
	if claims.System {
		return http.StatusUnauthorized, nil, errors.ErrorData(logutils.StatusInvalid, "system claim", nil)
	}

	err = auth.tokenAuth.AuthorizeRequestScope(claims, req)
	if err != nil {
		return http.StatusForbidden, nil, errors.WrapErrorAction(typeCheckScope, logutils.TypeRequest, nil, err)
	}

	return http.StatusOK, claims, nil
}

// GetTokenAuth exposes the TokenAuth for the handler
func (auth *ServicesAuth) GetTokenAuth() *tokenauth.TokenAuth {
	return auth.tokenAuth
}

func newServicesAuth(serviceRegManager *authservice.ServiceRegManager, serviceID string) (*ServicesAuth, error) {
	servicesScopeAuth := authorization.NewCasbinScopeAuthorization("driver/web/authorization_services_policy.csv", serviceID)
	servicesPermissionAuth := authorization.NewCasbinStringAuthorization("driver/web/authorization_services_policy.csv")

	servicesTokenAuth, err := tokenauth.NewTokenAuth(true, serviceRegManager, servicesPermissionAuth, servicesScopeAuth)

	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "token auth for servicesAuth", nil, err)
	}

	auth := ServicesAuth{tokenAuth: servicesTokenAuth}
	return &auth, nil
}

// AdminAuth entity
type AdminAuth struct {
	tokenAuth *tokenauth.TokenAuth
}

// Check checks the token in the provided request
func (auth *AdminAuth) Check(req *http.Request) (int, *tokenauth.Claims, error) {
	claims, err := auth.tokenAuth.CheckRequestTokens(req)
	if err != nil {
		return http.StatusUnauthorized, nil, errors.WrapErrorAction(typeCheckAdminAuthRequestToken, logutils.TypeToken, nil, err)
	}

	if !claims.Admin {
		return http.StatusUnauthorized, nil, errors.ErrorData(logutils.StatusInvalid, "admin claim", nil)
	}

	return http.StatusOK, claims, nil
}

// GetTokenAuth exposes the TokenAuth for the handler
func (auth *AdminAuth) GetTokenAuth() *tokenauth.TokenAuth {
	return auth.tokenAuth
}

func newAdminAuth(serviceRegManager *authservice.ServiceRegManager) (*AdminAuth, error) {
	adminPermissionAuth := authorization.NewCasbinStringAuthorization("driver/web/authorization_admin_policy.csv")
	adminTokenAuth, err := tokenauth.NewTokenAuth(true, serviceRegManager, adminPermissionAuth, nil)

	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "token auth for adminAuth", nil, err)
	}

	auth := AdminAuth{tokenAuth: adminTokenAuth}
	return &auth, nil
}

func newEncAuth(serviceRegManager *authservice.ServiceRegManager) (*tokenauth.StandardHandler, error) {
	encPermissionAuth := authorization.NewCasbinStringAuthorization("driver/web/authorization_enc_policy.csv")
	encTokenAuth, err := tokenauth.NewTokenAuth(true, serviceRegManager, encPermissionAuth, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "token auth for encAuth", nil, err)
	}

	auth := tokenauth.NewStandardHandler(*encTokenAuth)
	return &auth, nil
}

// BBsAuth entity
type BBsAuth struct {
	tokenAuth *tokenauth.TokenAuth
}

// Check checks the token in the provided request
func (auth *BBsAuth) Check(req *http.Request) (int, *tokenauth.Claims, error) {
	claims, err := auth.tokenAuth.CheckRequestTokens(req)
	if err != nil {
		return http.StatusUnauthorized, nil, errors.WrapErrorAction(typeCheckBBsAuthRequestToken, logutils.TypeToken, nil, err)
	}

	if !claims.Service {
		return http.StatusUnauthorized, nil, errors.ErrorData(logutils.StatusInvalid, "service claim", nil)
	}

	if !claims.FirstParty {
		return http.StatusUnauthorized, nil, errors.ErrorData(logutils.StatusInvalid, "first party claim", nil)
	}

	return http.StatusOK, claims, nil
}

// GetTokenAuth exposes the TokenAuth for the handler
func (auth *BBsAuth) GetTokenAuth() *tokenauth.TokenAuth {
	return auth.tokenAuth
}

func newBBsAuth(serviceRegManager *authservice.ServiceRegManager) (*BBsAuth, error) {
	bbsPermissionAuth := authorization.NewCasbinStringAuthorization("driver/web/authorization_bbs_policy.csv")
	bbsTokenAuth, err := tokenauth.NewTokenAuth(true, serviceRegManager, bbsPermissionAuth, nil)

	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "token auth for bbsAuth", nil, err)
	}

	auth := BBsAuth{tokenAuth: bbsTokenAuth}
	return &auth, nil
}

// TPsAuth entity
type TPsAuth struct {
	tokenAuth *tokenauth.TokenAuth
}

// Check checks the token in the provided request
func (auth *TPsAuth) Check(req *http.Request) (int, *tokenauth.Claims, error) {
	claims, err := auth.tokenAuth.CheckRequestTokens(req)
	if err != nil {
		return http.StatusUnauthorized, nil, errors.WrapErrorAction(typeCheckTPsAuthRequestToken, logutils.TypeToken, nil, err)
	}

	if !claims.Service {
		return http.StatusUnauthorized, nil, errors.ErrorData(logutils.StatusInvalid, "service claim", nil)
	}

	if claims.FirstParty {
		return http.StatusUnauthorized, nil, errors.ErrorData(logutils.StatusInvalid, "first party claim", nil)
	}

	return http.StatusOK, claims, nil
}

// GetTokenAuth exposes the TokenAuth for the handler
func (auth *TPsAuth) GetTokenAuth() *tokenauth.TokenAuth {
	return auth.tokenAuth
}

func newTPsAuth(serviceRegManager *authservice.ServiceRegManager) (*TPsAuth, error) {
	tpsPermissionAuth := authorization.NewCasbinStringAuthorization("driver/web/authorization_tps_policy.csv")
	tpsTokenAuth, err := tokenauth.NewTokenAuth(true, serviceRegManager, tpsPermissionAuth, nil)

	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "token auth for tpsAuth", nil, err)
	}

	auth := TPsAuth{tokenAuth: tpsTokenAuth}
	return &auth, nil
}

// SystemAuth entity
type SystemAuth struct {
	tokenAuth *tokenauth.TokenAuth
}

// Check checks the token in the provided request
func (auth *SystemAuth) Check(req *http.Request) (int, *tokenauth.Claims, error) {
	claims, err := auth.tokenAuth.CheckRequestTokens(req)
	if err != nil {
		return http.StatusUnauthorized, nil, errors.WrapErrorAction(typeCheckSystemAuthRequestToken, logutils.TypeToken, nil, err)
	}

	if !claims.System {
		return http.StatusUnauthorized, nil, errors.ErrorData(logutils.StatusInvalid, "system claim", nil)
	}

	return http.StatusOK, claims, nil
}

// GetTokenAuth exposes the TokenAuth for the handler
func (auth *SystemAuth) GetTokenAuth() *tokenauth.TokenAuth {
	return auth.tokenAuth
}

func newSystemAuth(serviceRegManager *authservice.ServiceRegManager) (*SystemAuth, error) {
	systemPermissionAuth := authorization.NewCasbinStringAuthorization("driver/web/authorization_system_policy.csv")
	systemTokenAuth, err := tokenauth.NewTokenAuth(true, serviceRegManager, systemPermissionAuth, nil)

	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "token auth for systemAuth", nil, err)
	}

	auth := SystemAuth{tokenAuth: systemTokenAuth}
	return &auth, nil
}
