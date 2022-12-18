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

// Auth handler
type Auth struct {
	services *tokenauth.Handlers
	admin    *tokenauth.Handlers
	enc      *tokenauth.Handlers
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
		return nil, errors.WrapErrorAction(logutils.ActionCreate, "admin auth", nil, err)
	}
	adminHandlers := tokenauth.NewHandlers(adminAuth)

	encAuth, err := newEncAuth(serviceRegManager)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, "enc auth", nil, err)
	}
	encHandlers := tokenauth.NewHandlers(encAuth)

	bbsAuth, err := newBBsAuth(serviceRegManager)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, "bbs auth", nil, err)
	}
	bbsHandlers := tokenauth.NewHandlers(bbsAuth)

	tpsAuth, err := newTPsAuth(serviceRegManager)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, "tps auth", nil, err)
	}
	tpsHandlers := tokenauth.NewHandlers(tpsAuth)

	systemAuth, err := newSystemAuth(serviceRegManager)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, "auth handler", nil, err)
	}
	systemHandlers := tokenauth.NewHandlers(systemAuth)

	auth := Auth{services: &serviceHandlers, admin: &adminHandlers, enc: &encHandlers, bbs: &bbsHandlers, tps: &tpsHandlers, system: &systemHandlers}

	return &auth, nil
}

// ServicesAuth

func newServicesAuth(serviceRegManager *authservice.ServiceRegManager, serviceID string) (*tokenauth.StandardHandler, error) {
	servicesScopeAuth := authorization.NewCasbinScopeAuthorization("driver/web/authorization_services_policy.csv", serviceID)
	servicesPermissionAuth := authorization.NewCasbinStringAuthorization("driver/web/authorization_services_policy.csv")

	servicesTokenAuth, err := tokenauth.NewTokenAuth(true, serviceRegManager, servicesPermissionAuth, servicesScopeAuth)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "token auth for servicesAuth", nil, err)
	}

	check := func(claims *tokenauth.Claims, req *http.Request) (int, error) {
		if claims.Admin {
			return http.StatusUnauthorized, errors.ErrorData(logutils.StatusInvalid, "admin claim", nil)
		}
		if claims.System {
			return http.StatusUnauthorized, errors.ErrorData(logutils.StatusInvalid, "system claim", nil)
		}

		return http.StatusOK, nil
	}

	auth := tokenauth.NewScopeHandler(*servicesTokenAuth, check)
	return &auth, nil
}

// AdminAuth

func newAdminAuth(serviceRegManager *authservice.ServiceRegManager) (*tokenauth.StandardHandler, error) {
	adminPermissionAuth := authorization.NewCasbinStringAuthorization("driver/web/authorization_admin_policy.csv")
	adminTokenAuth, err := tokenauth.NewTokenAuth(true, serviceRegManager, adminPermissionAuth, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "token auth for adminAuth", nil, err)
	}

	check := func(claims *tokenauth.Claims, req *http.Request) (int, error) {
		if !claims.Admin {
			return http.StatusUnauthorized, errors.ErrorData(logutils.StatusInvalid, "admin claim", nil)
		}

		return http.StatusOK, nil
	}

	auth := tokenauth.NewStandardHandler(*adminTokenAuth, check)
	return &auth, nil
}

// EncAuth

func newEncAuth(serviceRegManager *authservice.ServiceRegManager) (*tokenauth.StandardHandler, error) {
	encPermissionAuth := authorization.NewCasbinStringAuthorization("driver/web/authorization_enc_policy.csv")
	encTokenAuth, err := tokenauth.NewTokenAuth(true, serviceRegManager, encPermissionAuth, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "token auth for encAuth", nil, err)
	}

	auth := tokenauth.NewStandardHandler(*encTokenAuth, nil)
	return &auth, nil
}

// BBsAuth

func newBBsAuth(serviceRegManager *authservice.ServiceRegManager) (*tokenauth.StandardHandler, error) {
	bbsPermissionAuth := authorization.NewCasbinStringAuthorization("driver/web/authorization_bbs_policy.csv")
	bbsTokenAuth, err := tokenauth.NewTokenAuth(true, serviceRegManager, bbsPermissionAuth, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "token auth for bbsAuth", nil, err)
	}

	check := func(claims *tokenauth.Claims, req *http.Request) (int, error) {
		if !claims.Service {
			return http.StatusUnauthorized, errors.ErrorData(logutils.StatusInvalid, "service claim", nil)
		}

		if !claims.FirstParty {
			return http.StatusUnauthorized, errors.ErrorData(logutils.StatusInvalid, "first party claim", nil)
		}

		return http.StatusOK, nil
	}

	auth := tokenauth.NewStandardHandler(*bbsTokenAuth, check)
	return &auth, nil
}

// TPsAuth

func newTPsAuth(serviceRegManager *authservice.ServiceRegManager) (*tokenauth.StandardHandler, error) {
	tpsPermissionAuth := authorization.NewCasbinStringAuthorization("driver/web/authorization_tps_policy.csv")
	tpsTokenAuth, err := tokenauth.NewTokenAuth(true, serviceRegManager, tpsPermissionAuth, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "token auth for tpsAuth", nil, err)
	}

	check := func(claims *tokenauth.Claims, req *http.Request) (int, error) {
		if !claims.Service {
			return http.StatusUnauthorized, errors.ErrorData(logutils.StatusInvalid, "service claim", nil)
		}

		if claims.FirstParty {
			return http.StatusUnauthorized, errors.ErrorData(logutils.StatusInvalid, "first party claim", nil)
		}

		return http.StatusOK, nil
	}

	auth := tokenauth.NewStandardHandler(*tpsTokenAuth, check)
	return &auth, nil
}

// SystemAuth

func newSystemAuth(serviceRegManager *authservice.ServiceRegManager) (*tokenauth.StandardHandler, error) {
	systemPermissionAuth := authorization.NewCasbinStringAuthorization("driver/web/authorization_system_policy.csv")
	systemTokenAuth, err := tokenauth.NewTokenAuth(true, serviceRegManager, systemPermissionAuth, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "token auth for systemAuth", nil, err)
	}

	check := func(claims *tokenauth.Claims, req *http.Request) (int, error) {
		if !claims.System {
			return http.StatusUnauthorized, errors.ErrorData(logutils.StatusInvalid, "system claim", nil)
		}

		return http.StatusOK, nil
	}

	auth := tokenauth.NewStandardHandler(*systemTokenAuth, check)
	return &auth, nil
}
