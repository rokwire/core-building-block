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
	"core-building-block/core"
	"net/http"

	"github.com/rokwire/core-auth-library-go/v2/authorization"
	"github.com/rokwire/core-auth-library-go/v2/authservice"
	"github.com/rokwire/core-auth-library-go/v2/tokenauth"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

const (
	typeCheckPermission               logutils.MessageActionType = "checking permission"
	typeCheckScope                    logutils.MessageActionType = "checking scope"
	typeCheckSystemAuthRequestToken   logutils.MessageActionType = "checking system auth"
	typeCheckTPsAuthRequestToken      logutils.MessageActionType = "checking tps auth"
	typeCheckBBsAuthRequestToken      logutils.MessageActionType = "checking bbs auth"
	typeCheckAdminAuthRequestToken    logutils.MessageActionType = "checking admin auth"
	typeCheckServicesAuthRequestToken logutils.MessageActionType = "checking services auth"
)

// Auth handler
type Auth struct {
	services *TokenAuthHandlers
	admin    *TokenAuthHandlers
	encAuth  *EncAuth
	bbs      *TokenAuthHandlers
	tps      *TokenAuthHandlers
	system   *TokenAuthHandlers

	logger *logs.Logger
}

// Authorization is an interface for auth types
type Authorization interface {
	check(req *http.Request) (int, *tokenauth.Claims, error)
	start()
}

// TokenAuthorization is an interface for auth types
type TokenAuthorization interface {
	Authorization
	getTokenAuth() *tokenauth.TokenAuth
}

// Start starts the auth module
func (auth *Auth) Start() error {
	auth.logger.Info("Auth -> start")

	auth.services.start()
	auth.admin.start()
	auth.encAuth.start()
	auth.bbs.start()
	auth.tps.start()
	auth.system.start()

	return nil
}

// NewAuth creates new auth handler
func NewAuth(coreAPIs *core.APIs, serviceID string, serviceRegManager *authservice.ServiceRegManager, logger *logs.Logger) (*Auth, error) {
	servicesAuth, err := newServicesAuth(coreAPIs, serviceRegManager, serviceID, logger)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, "services auth", nil, err)
	}
	serviceHandlers, err := newTokenAuthHandlers(servicesAuth)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "services auth handlers", nil, err)
	}

	adminAuth, err := newAdminAuth(coreAPIs, serviceRegManager, logger)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "admin auth", nil, err)
	}
	adminHandlers, err := newTokenAuthHandlers(adminAuth)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "admin auth handlers", nil, err)
	}

	encAuth := newEncAuth(coreAPIs, logger)

	bbsAuth, err := newBBsAuth(coreAPIs, serviceRegManager, logger)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "bbs auth", nil, err)
	}
	bbsHandlers, err := newTokenAuthHandlers(bbsAuth)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "bbs auth handlers", nil, err)
	}

	tpsAuth, err := newTPsAuth(coreAPIs, serviceRegManager, logger)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "tps auth", nil, err)
	}
	tpsHandlers, err := newTokenAuthHandlers(tpsAuth)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "tps auth handlers", nil, err)
	}

	systemAuth, err := newSystemAuth(coreAPIs, serviceRegManager, logger)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "auth handler", nil, err)
	}
	systemHandlers, err := newTokenAuthHandlers(systemAuth)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "system auth handlers", nil, err)
	}

	auth := Auth{services: serviceHandlers, admin: adminHandlers, encAuth: encAuth, bbs: bbsHandlers, tps: tpsHandlers, system: systemHandlers, logger: logger}

	return &auth, nil
}

// TokenAuthHandlers represents token auth handlers
type TokenAuthHandlers struct {
	standard      TokenAuthorization
	permissions   *PermissionsAuth
	user          *UserAuth
	authenticated *AuthenticatedAuth
}

func (auth *TokenAuthHandlers) start() {
	auth.standard.start()
	auth.permissions.start()
	auth.user.start()
	auth.authenticated.start()
}

// newTokenAuthHandlers creates new auth handlers for a
func newTokenAuthHandlers(auth TokenAuthorization) (*TokenAuthHandlers, error) {
	permissionsAuth := newPermissionsAuth(auth)
	userAuth := newUserAuth(auth)
	authenticatedAuth := newAuthenticatedAuth(*userAuth)

	authWrappers := TokenAuthHandlers{standard: auth, permissions: permissionsAuth, user: userAuth, authenticated: authenticatedAuth}
	return &authWrappers, nil
}

// ServicesAuth entity
type ServicesAuth struct {
	coreAPIs  *core.APIs
	tokenAuth *tokenauth.TokenAuth
	logger    *logs.Logger
}

func (auth *ServicesAuth) start() {
	auth.logger.Info("ServicesAuth -> start")
}

func (auth *ServicesAuth) check(req *http.Request) (int, *tokenauth.Claims, error) {
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

func (auth *ServicesAuth) getTokenAuth() *tokenauth.TokenAuth {
	return auth.tokenAuth
}

func newServicesAuth(coreAPIs *core.APIs, serviceRegManager *authservice.ServiceRegManager, serviceID string, logger *logs.Logger) (*ServicesAuth, error) {
	servicesScopeAuth := authorization.NewCasbinScopeAuthorization("driver/web/authorization_services_policy.csv", serviceID)
	servicesPermissionAuth := authorization.NewCasbinStringAuthorization("driver/web/authorization_services_policy.csv")

	servicesTokenAuth, err := tokenauth.NewTokenAuth(true, serviceRegManager, servicesPermissionAuth, servicesScopeAuth)

	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "token auth for servicesAuth", nil, err)
	}

	auth := ServicesAuth{coreAPIs: coreAPIs, tokenAuth: servicesTokenAuth, logger: logger}
	return &auth, nil
}

// AdminAuth entity
type AdminAuth struct {
	coreAPIs  *core.APIs
	tokenAuth *tokenauth.TokenAuth
	logger    *logs.Logger
}

func (auth *AdminAuth) start() {
	auth.logger.Info("AdminAuth -> start")
}

func (auth *AdminAuth) check(req *http.Request) (int, *tokenauth.Claims, error) {
	claims, err := auth.tokenAuth.CheckRequestTokens(req)
	if err != nil {
		return http.StatusUnauthorized, nil, errors.WrapErrorAction(typeCheckAdminAuthRequestToken, logutils.TypeToken, nil, err)
	}

	if !claims.Admin {
		return http.StatusUnauthorized, nil, errors.ErrorData(logutils.StatusInvalid, "admin claim", nil)
	}

	return http.StatusOK, claims, nil
}

func (auth *AdminAuth) getTokenAuth() *tokenauth.TokenAuth {
	return auth.tokenAuth
}

func newAdminAuth(coreAPIs *core.APIs, serviceRegManager *authservice.ServiceRegManager, logger *logs.Logger) (*AdminAuth, error) {
	adminPermissionAuth := authorization.NewCasbinStringAuthorization("driver/web/authorization_admin_policy.csv")
	adminTokenAuth, err := tokenauth.NewTokenAuth(true, serviceRegManager, adminPermissionAuth, nil)

	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "token auth for adminAuth", nil, err)
	}

	auth := AdminAuth{coreAPIs: coreAPIs, tokenAuth: adminTokenAuth, logger: logger}
	return &auth, nil
}

// EncAuth entity
type EncAuth struct {
	coreAPIs *core.APIs

	logger *logs.Logger
}

func (auth *EncAuth) start() {
	auth.logger.Info("EncAuth -> start")
}

func newEncAuth(coreAPIs *core.APIs, logger *logs.Logger) *EncAuth {
	auth := EncAuth{coreAPIs: coreAPIs, logger: logger}
	return &auth
}

// BBsAuth entity
type BBsAuth struct {
	coreAPIs  *core.APIs
	tokenAuth *tokenauth.TokenAuth
	logger    *logs.Logger
}

func (auth *BBsAuth) start() {
	auth.logger.Info("BBsAuth -> start")
}

func (auth *BBsAuth) check(req *http.Request) (int, *tokenauth.Claims, error) {
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

func (auth *BBsAuth) getTokenAuth() *tokenauth.TokenAuth {
	return auth.tokenAuth
}

func newBBsAuth(coreAPIs *core.APIs, serviceRegManager *authservice.ServiceRegManager, logger *logs.Logger) (*BBsAuth, error) {
	bbsPermissionAuth := authorization.NewCasbinStringAuthorization("driver/web/authorization_bbs_policy.csv")
	bbsTokenAuth, err := tokenauth.NewTokenAuth(true, serviceRegManager, bbsPermissionAuth, nil)

	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "token auth for bbsAuth", nil, err)
	}

	auth := BBsAuth{coreAPIs: coreAPIs, tokenAuth: bbsTokenAuth, logger: logger}
	return &auth, nil
}

// TPsAuth entity
type TPsAuth struct {
	coreAPIs  *core.APIs
	tokenAuth *tokenauth.TokenAuth
	logger    *logs.Logger
}

func (auth *TPsAuth) start() {
	auth.logger.Info("TPsAuth -> start")
}

func (auth *TPsAuth) check(req *http.Request) (int, *tokenauth.Claims, error) {
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

func (auth *TPsAuth) getTokenAuth() *tokenauth.TokenAuth {
	return auth.tokenAuth
}

func newTPsAuth(coreAPIs *core.APIs, serviceRegManager *authservice.ServiceRegManager, logger *logs.Logger) (*TPsAuth, error) {
	tpsPermissionAuth := authorization.NewCasbinStringAuthorization("driver/web/authorization_tps_policy.csv")
	tpsTokenAuth, err := tokenauth.NewTokenAuth(true, serviceRegManager, tpsPermissionAuth, nil)

	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "token auth for tpsAuth", nil, err)
	}

	auth := TPsAuth{coreAPIs: coreAPIs, tokenAuth: tpsTokenAuth, logger: logger}
	return &auth, nil
}

// SystemAuth entity
type SystemAuth struct {
	coreAPIs  *core.APIs
	tokenAuth *tokenauth.TokenAuth
	logger    *logs.Logger
}

func (auth *SystemAuth) start() {
	auth.logger.Info("SystemAuth -> start")
}

func (auth *SystemAuth) check(req *http.Request) (int, *tokenauth.Claims, error) {
	claims, err := auth.tokenAuth.CheckRequestTokens(req)
	if err != nil {
		return http.StatusUnauthorized, nil, errors.WrapErrorAction(typeCheckSystemAuthRequestToken, logutils.TypeToken, nil, err)
	}

	if !claims.System {
		return http.StatusUnauthorized, nil, errors.ErrorData(logutils.StatusInvalid, "system claim", nil)
	}

	return http.StatusOK, claims, nil
}

func (auth *SystemAuth) getTokenAuth() *tokenauth.TokenAuth {
	return auth.tokenAuth
}

func newSystemAuth(coreAPIs *core.APIs, serviceRegManager *authservice.ServiceRegManager, logger *logs.Logger) (*SystemAuth, error) {
	systemPermissionAuth := authorization.NewCasbinStringAuthorization("driver/web/authorization_system_policy.csv")
	systemTokenAuth, err := tokenauth.NewTokenAuth(true, serviceRegManager, systemPermissionAuth, nil)

	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionStart, "token auth for systemAuth", nil, err)
	}

	auth := SystemAuth{coreAPIs: coreAPIs, tokenAuth: systemTokenAuth, logger: logger}
	return &auth, nil
}

// PermissionsAuth entity
// This enforces that the user has permissions matching the policy
type PermissionsAuth struct {
	auth TokenAuthorization
}

func (a *PermissionsAuth) start() {}

func (a *PermissionsAuth) check(req *http.Request) (int, *tokenauth.Claims, error) {
	status, claims, err := a.auth.check(req)

	if err == nil && claims != nil {
		err = a.auth.getTokenAuth().AuthorizeRequestPermissions(claims, req)
		if err != nil {
			return http.StatusForbidden, nil, errors.WrapErrorAction(typeCheckPermission, logutils.TypeRequest, nil, err)
		}
	}

	return status, claims, err
}

func newPermissionsAuth(auth TokenAuthorization) *PermissionsAuth {
	permissionsAuth := PermissionsAuth{auth: auth}
	return &permissionsAuth
}

// UserAuth entity
// This enforces that the user is not anonymous
type UserAuth struct {
	auth Authorization
}

func (a *UserAuth) start() {}

func (a *UserAuth) check(req *http.Request) (int, *tokenauth.Claims, error) {
	status, claims, err := a.auth.check(req)

	if err == nil && claims != nil {
		if claims.Anonymous {
			return http.StatusForbidden, nil, errors.New("token must not be anonymous")
		}
	}

	return status, claims, err
}

func newUserAuth(auth Authorization) *UserAuth {
	userAuth := UserAuth{auth: auth}
	return &userAuth
}

// AuthenticatedAuth entity
// This enforces that the token was the result of direct user authentication. It should be used to protect sensitive account settings
type AuthenticatedAuth struct {
	userAuth UserAuth
}

func (auth *AuthenticatedAuth) start() {}

func (auth *AuthenticatedAuth) check(req *http.Request) (int, *tokenauth.Claims, error) {
	status, claims, err := auth.userAuth.check(req)

	if err == nil && claims != nil {
		if !claims.Authenticated {
			return http.StatusForbidden, nil, errors.New("user must login again")
		}
	}

	return status, claims, err
}

func newAuthenticatedAuth(userAuth UserAuth) *AuthenticatedAuth {
	auth := AuthenticatedAuth{userAuth: userAuth}
	return &auth
}
