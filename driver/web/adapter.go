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
	"bytes"
	"context"
	"core-building-block/core"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"time"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"
	"github.com/getkin/kin-openapi/routers"
	"github.com/getkin/kin-openapi/routers/gorillamux"
	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logs"
	"github.com/rokwire/logging-library-go/v2/logutils"
	"gopkg.in/yaml.v2"

	"github.com/gorilla/mux"

	"github.com/rokwire/core-auth-library-go/v3/authservice"
	"github.com/rokwire/core-auth-library-go/v3/tokenauth"
	"github.com/rokwire/core-auth-library-go/v3/webauth"

	httpSwagger "github.com/swaggo/http-swagger"
)

// Adapter entity
type Adapter struct {
	env  string
	port string

	productionServerURL  string
	testServerURL        string
	developmentServerURL string

	cachedYamlDoc []byte

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

	corsAllowedOrigins []string
	corsAllowedHeaders []string
}

type handlerFunc = func(*logs.Log, *http.Request, *tokenauth.Claims) logs.HTTPResponse

// Start starts the module
func (we Adapter) Start() {

	//add listener to the application
	we.coreAPIs.AddListener(&AppListener{&we})

	// we.auth.Start()

	router := mux.NewRouter().StrictSlash(true)
	subRouter := router.PathPrefix("/core").Subrouter()

	//docs
	subRouter.PathPrefix("/doc/ui").Handler(we.serveDocUI()) //Public
	subRouter.HandleFunc("/doc", we.serveDoc)                //Public
	///

	//ui
	subRouter.HandleFunc("/ui/credential/reset", we.serveResetCredential)                                                     //Public
	subRouter.HandleFunc("/ui/webauthn-test", we.serveWebAuthnTest)                                                           //Public
	subRouter.HandleFunc("/ui/credential/verify", we.uiWrapFunc(we.servicesApisHandler.verifyCredential, nil)).Methods("GET") //Public (validates code)
	// subRouter.HandleFunc("/ui/webauthn-test", we.serveWebAuthnTest)                                                           //Public

	///default ///
	subRouter.HandleFunc("/version", we.wrapFunc(we.defaultApisHandler.getVersion, nil)).Methods("GET")                                      //Public
	subRouter.HandleFunc("/.well-known/openid-configuration", we.wrapFunc(we.defaultApisHandler.getOpenIDConfiguration, nil)).Methods("GET") //Public
	///

	///services ///
	servicesSubRouter := subRouter.PathPrefix("/services").Subrouter()
	servicesSubRouter.HandleFunc("/auth/login", we.wrapFunc(we.servicesApisHandler.login, nil)).Methods("POST")        //Requires API key in request
	servicesSubRouter.HandleFunc("/auth/mfa", we.wrapFunc(we.servicesApisHandler.loginMFA, nil)).Methods("POST")       //Requires API key in request
	servicesSubRouter.HandleFunc("/auth/login-url", we.wrapFunc(we.servicesApisHandler.loginURL, nil)).Methods("POST") //Requires API key in request
	servicesSubRouter.HandleFunc("/auth/refresh", we.wrapFunc(we.servicesApisHandler.refresh, nil)).Methods("POST")    //Requires API key in request
	servicesSubRouter.HandleFunc("/auth/logout", we.wrapFunc(we.servicesApisHandler.logout, we.auth.services.User)).Methods("POST")
	servicesSubRouter.HandleFunc("/auth/account/exists", we.wrapFunc(we.servicesApisHandler.accountExists, nil)).Methods("POST")  //Requires API key in request
	servicesSubRouter.HandleFunc("/auth/account/can-sign-in", we.wrapFunc(we.servicesApisHandler.canSignIn, nil)).Methods("POST") //Requires API key in request
	servicesSubRouter.HandleFunc("/auth/account/can-link", we.wrapFunc(we.servicesApisHandler.canLink, nil)).Methods("POST")      //Requires API key in request
	servicesSubRouter.HandleFunc("/auth/account/auth-type/link", we.wrapFunc(we.servicesApisHandler.linkAccountAuthType, we.auth.services.Authenticated)).Methods("POST")
	servicesSubRouter.HandleFunc("/auth/account/auth-type/link", we.wrapFunc(we.servicesApisHandler.unlinkAccountAuthType, we.auth.services.Authenticated)).Methods("DELETE")
	servicesSubRouter.HandleFunc("/auth/credential/verify", we.wrapFunc(we.servicesApisHandler.verifyCredential, nil)).Methods("GET")                   //Public (validates code)
	servicesSubRouter.HandleFunc("/auth/credential/send-verify", we.wrapFunc(we.servicesApisHandler.sendVerifyCredential, nil)).Methods("POST")         //Requires API key in request
	servicesSubRouter.HandleFunc("/auth/credential/forgot/initiate", we.wrapFunc(we.servicesApisHandler.forgotCredentialInitiate, nil)).Methods("POST") //Requires API key in request
	servicesSubRouter.HandleFunc("/auth/credential/forgot/complete", we.wrapFunc(we.servicesApisHandler.forgotCredentialComplete, nil)).Methods("POST") //Public
	servicesSubRouter.HandleFunc("/auth/credential/update", we.wrapFunc(we.servicesApisHandler.updateCredential, we.auth.services.Authenticated)).Methods("POST")
	servicesSubRouter.HandleFunc("/auth/verify-mfa", we.wrapFunc(we.servicesApisHandler.verifyMFA, we.auth.services.User)).Methods("POST")
	servicesSubRouter.HandleFunc("/auth/authorize-service", we.wrapFunc(we.servicesApisHandler.authorizeService, we.auth.services.User)).Methods("POST")
	servicesSubRouter.HandleFunc("/auth/service-regs", we.wrapFunc(we.servicesApisHandler.getServiceRegistrations, we.auth.services.Standard)).Methods("GET")
	servicesSubRouter.HandleFunc("/accounts", we.wrapFunc(we.servicesApisHandler.getAccounts, we.auth.services.Permissions)).Methods("GET")
	servicesSubRouter.HandleFunc("/accounts", we.wrapFunc(we.servicesApisHandler.createAdminAccount, we.auth.services.Permissions)).Methods("POST")
	servicesSubRouter.HandleFunc("/accounts", we.wrapFunc(we.servicesApisHandler.updateAdminAccount, we.auth.services.Permissions)).Methods("PUT")
	servicesSubRouter.HandleFunc("/accounts/public", we.wrapFunc(we.servicesApisHandler.getPublicAccounts, we.auth.services.Standard)).Methods("GET")
	servicesSubRouter.HandleFunc("/account", we.wrapFunc(we.servicesApisHandler.deleteAccount, we.auth.services.Standard)).Methods("DELETE")
	servicesSubRouter.HandleFunc("/account", we.wrapFunc(we.servicesApisHandler.getAccount, we.auth.services.Standard)).Methods("GET")
	servicesSubRouter.HandleFunc("/account/mfa", we.wrapFunc(we.servicesApisHandler.getMFATypes, we.auth.services.User)).Methods("GET")
	servicesSubRouter.HandleFunc("/account/mfa", we.wrapFunc(we.servicesApisHandler.addMFAType, we.auth.services.Authenticated)).Methods("POST")
	servicesSubRouter.HandleFunc("/account/mfa", we.wrapFunc(we.servicesApisHandler.removeMFAType, we.auth.services.Authenticated)).Methods("DELETE")
	servicesSubRouter.HandleFunc("/account/preferences", we.wrapFunc(we.servicesApisHandler.updateAccountPreferences, we.auth.services.Standard)).Methods("PUT")
	servicesSubRouter.HandleFunc("/account/preferences", we.wrapFunc(we.servicesApisHandler.getPreferences, we.auth.services.Standard)).Methods("GET")
	servicesSubRouter.HandleFunc("/account/profile", we.wrapFunc(we.servicesApisHandler.getProfile, we.auth.services.User)).Methods("GET")
	servicesSubRouter.HandleFunc("/account/profile", we.wrapFunc(we.servicesApisHandler.updateProfile, we.auth.services.User)).Methods("PUT")
	servicesSubRouter.HandleFunc("/account/privacy", we.wrapFunc(we.servicesApisHandler.updatePrivacy, we.auth.services.User)).Methods("PUT")
	servicesSubRouter.HandleFunc("/account/system-configs", we.wrapFunc(we.servicesApisHandler.getAccountSystemConfigs, we.auth.services.Standard)).Methods("GET")
	servicesSubRouter.HandleFunc("/account/username", we.wrapFunc(we.servicesApisHandler.updateAccountUsername, we.auth.services.User)).Methods("PUT")
	servicesSubRouter.HandleFunc("/account/follow", we.wrapFunc(we.servicesApisHandler.addFollow, we.auth.services.User)).Methods("POST")
	servicesSubRouter.HandleFunc("/account/follow/{id}", we.wrapFunc(we.servicesApisHandler.deleteFollow, we.auth.services.User)).Methods("DELETE")
	servicesSubRouter.HandleFunc("/test", we.wrapFunc(we.servicesApisHandler.getTest, nil)).Methods("GET")                       //Public
	servicesSubRouter.HandleFunc("/app-configs", we.wrapFunc(we.servicesApisHandler.getApplicationConfigs, nil)).Methods("POST") //Requires API key in request
	servicesSubRouter.HandleFunc("/app-configs/organization", we.wrapFunc(we.servicesApisHandler.getApplicationOrgConfigs, we.auth.services.Standard)).Methods("POST")

	// DEPRECATED
	servicesSubRouter.HandleFunc("/application/configs", we.wrapFunc(we.servicesApisHandler.getApplicationConfigs, nil)).Methods("POST") //Requires API key in request
	servicesSubRouter.HandleFunc("/application/organization/configs", we.wrapFunc(we.servicesApisHandler.getApplicationOrgConfigs, we.auth.services.Standard)).Methods("POST")
	///

	///

	///admin ///
	adminSubrouter := subRouter.PathPrefix("/admin").Subrouter()
	adminSubrouter.HandleFunc("/test", we.wrapFunc(we.adminApisHandler.getTest, we.auth.admin.Permissions)).Methods("GET")
	adminSubrouter.HandleFunc("/test-model", we.wrapFunc(we.adminApisHandler.getTestModel, we.auth.admin.Permissions)).Methods("GET")

	adminSubrouter.HandleFunc("/auth/login", we.wrapFunc(we.adminApisHandler.login, nil)).Methods("POST")
	adminSubrouter.HandleFunc("/auth/mfa", we.wrapFunc(we.adminApisHandler.loginMFA, nil)).Methods("POST")
	adminSubrouter.HandleFunc("/auth/login-url", we.wrapFunc(we.adminApisHandler.loginURL, nil)).Methods("POST")
	adminSubrouter.HandleFunc("/auth/refresh", we.wrapFunc(we.adminApisHandler.refresh, nil)).Methods("POST")
	adminSubrouter.HandleFunc("/auth/verify-mfa", we.wrapFunc(we.adminApisHandler.verifyMFA, we.auth.admin.User)).Methods("POST")
	adminSubrouter.HandleFunc("/auth/app-token", we.wrapFunc(we.adminApisHandler.getAppToken, we.auth.admin.User)).Methods("GET")

	adminSubrouter.HandleFunc("/configs/{id}", we.wrapFunc(we.adminApisHandler.getConfig, we.auth.admin.Permissions)).Methods("GET")
	adminSubrouter.HandleFunc("/configs", we.wrapFunc(we.adminApisHandler.getConfigs, we.auth.admin.Permissions)).Methods("GET")
	adminSubrouter.HandleFunc("/configs", we.wrapFunc(we.adminApisHandler.createConfig, we.auth.admin.Permissions)).Methods("POST")
	adminSubrouter.HandleFunc("/configs/{id}", we.wrapFunc(we.adminApisHandler.updateConfig, we.auth.admin.Permissions)).Methods("PUT")
	adminSubrouter.HandleFunc("/configs/{id}", we.wrapFunc(we.adminApisHandler.deleteConfig, we.auth.admin.Permissions)).Methods("DELETE")

	adminSubrouter.HandleFunc("/account", we.wrapFunc(we.adminApisHandler.getAccount, we.auth.admin.User)).Methods("GET")
	adminSubrouter.HandleFunc("/account/mfa", we.wrapFunc(we.adminApisHandler.getMFATypes, we.auth.admin.User)).Methods("GET")
	adminSubrouter.HandleFunc("/account/mfa", we.wrapFunc(we.adminApisHandler.addMFAType, we.auth.admin.Authenticated)).Methods("POST")
	adminSubrouter.HandleFunc("/account/mfa", we.wrapFunc(we.adminApisHandler.removeMFAType, we.auth.admin.Authenticated)).Methods("DELETE")
	adminSubrouter.HandleFunc("/account/username", we.wrapFunc(we.adminApisHandler.updateAccountUsername, we.auth.admin.User)).Methods("PUT")

	adminSubrouter.HandleFunc("/app-configs", we.wrapFunc(we.adminApisHandler.getAppConfigs, nil)).Methods("POST") //Requires API key in request
	adminSubrouter.HandleFunc("/app-configs/organization", we.wrapFunc(we.adminApisHandler.getAppConfigsForOrganization, we.auth.admin.User)).Methods("POST")

	adminSubrouter.HandleFunc("/organization/applications", we.wrapFunc(we.adminApisHandler.getApplications, we.auth.admin.User)).Methods("GET")

	adminSubrouter.HandleFunc("/application/login-sessions", we.wrapFunc(we.adminApisHandler.getApplicationLoginSessions, we.auth.admin.Permissions)).Methods("GET")

	adminSubrouter.HandleFunc("/application/configs", we.wrapFunc(we.adminApisHandler.getApplicationConfigs, we.auth.admin.Permissions)).Methods("GET")
	adminSubrouter.HandleFunc("/application/configs", we.wrapFunc(we.adminApisHandler.createApplicationConfig, we.auth.admin.Permissions)).Methods("POST")
	adminSubrouter.HandleFunc("/application/configs/{id}", we.wrapFunc(we.adminApisHandler.getApplicationConfig, we.auth.admin.Permissions)).Methods("GET")
	adminSubrouter.HandleFunc("/application/configs/{id}", we.wrapFunc(we.adminApisHandler.updateApplicationConfig, we.auth.admin.Permissions)).Methods("PUT")
	adminSubrouter.HandleFunc("/application/configs/{id}", we.wrapFunc(we.adminApisHandler.deleteApplicationConfig, we.auth.admin.Permissions)).Methods("DELETE")

	adminSubrouter.HandleFunc("/application/groups", we.wrapFunc(we.adminApisHandler.getApplicationGroups, we.auth.admin.Permissions)).Methods("GET")
	adminSubrouter.HandleFunc("/application/groups", we.wrapFunc(we.adminApisHandler.createApplicationGroup, we.auth.admin.Permissions)).Methods("POST")
	adminSubrouter.HandleFunc("/application/groups/{id}", we.wrapFunc(we.adminApisHandler.updateApplicationGroup, we.auth.admin.Permissions)).Methods("PUT")
	adminSubrouter.HandleFunc("/application/groups/{id}", we.wrapFunc(we.adminApisHandler.deleteApplicationGroup, we.auth.admin.Permissions)).Methods("DELETE")

	adminSubrouter.HandleFunc("/application/groups/{id}/accounts", we.wrapFunc(we.adminApisHandler.addAccountsToGroup, we.auth.admin.Permissions)).Methods("PUT")
	adminSubrouter.HandleFunc("/application/groups/{id}/accounts", we.wrapFunc(we.adminApisHandler.removeAccountsFromGroup, we.auth.admin.Permissions)).Methods("DELETE")

	adminSubrouter.HandleFunc("/application/roles", we.wrapFunc(we.adminApisHandler.getApplicationRoles, we.auth.admin.Permissions)).Methods("GET")
	adminSubrouter.HandleFunc("/application/roles", we.wrapFunc(we.adminApisHandler.createApplicationRole, we.auth.admin.Permissions)).Methods("POST")
	adminSubrouter.HandleFunc("/application/roles/{id}", we.wrapFunc(we.adminApisHandler.deleteApplicationRole, we.auth.admin.Permissions)).Methods("DELETE")
	adminSubrouter.HandleFunc("/application/roles/{id}", we.wrapFunc(we.adminApisHandler.updateApplicationRole, we.auth.admin.Permissions)).Methods("PUT")
	adminSubrouter.HandleFunc("/application/roles/{id}/permissions", we.wrapFunc(we.adminApisHandler.grantPermissionsToRole, we.auth.admin.Permissions)).Methods("PUT")

	adminSubrouter.HandleFunc("/application/permissions", we.wrapFunc(we.adminApisHandler.getApplicationPermissions, we.auth.admin.Permissions)).Methods("GET")

	adminSubrouter.HandleFunc("/application/accounts", we.wrapFunc(we.adminApisHandler.getApplicationAccounts, we.auth.admin.Permissions)).Methods("GET")
	adminSubrouter.HandleFunc("/application/accounts", we.wrapFunc(we.adminApisHandler.createAdminAccount, we.auth.admin.Permissions)).Methods("POST")
	adminSubrouter.HandleFunc("/application/accounts", we.wrapFunc(we.adminApisHandler.updateAdminAccount, we.auth.admin.Permissions)).Methods("PUT")

	adminSubrouter.HandleFunc("/application/filter/accounts", we.wrapFunc(we.adminApisHandler.getFilterAccounts, we.auth.admin.Permissions)).Methods("POST")
	adminSubrouter.HandleFunc("/application/filter/accounts/count", we.wrapFunc(we.adminApisHandler.getFilterAccountsCount, we.auth.admin.Permissions)).Methods("POST")

	adminSubrouter.HandleFunc("/application/accounts/{account_id}/login-sessions/{session_id}", we.wrapFunc(we.adminApisHandler.deleteApplicationLoginSession, we.auth.admin.Permissions)).Methods("DELETE")
	adminSubrouter.HandleFunc("/application/accounts/{id}/devices", we.wrapFunc(we.adminApisHandler.getApplicationAccountDevices, we.auth.admin.Permissions)).Methods("GET")
	adminSubrouter.HandleFunc("/application/accounts/{id}/permissions", we.wrapFunc(we.adminApisHandler.grantAccountPermissions, we.auth.admin.Permissions)).Methods("PUT")
	adminSubrouter.HandleFunc("/application/accounts/{id}/permissions", we.wrapFunc(we.adminApisHandler.revokeAccountPermissions, we.auth.admin.Permissions)).Methods("DELETE")
	adminSubrouter.HandleFunc("/application/accounts/{id}/roles", we.wrapFunc(we.adminApisHandler.grantAccountRoles, we.auth.admin.Permissions)).Methods("PUT")
	adminSubrouter.HandleFunc("/application/accounts/{id}/roles", we.wrapFunc(we.adminApisHandler.revokeAccountRoles, we.auth.admin.Permissions)).Methods("DELETE")
	adminSubrouter.HandleFunc("/application/accounts/{id}/system-configs", we.wrapFunc(we.adminApisHandler.getAccountSystemConfigs, we.auth.admin.Permissions)).Methods("GET")
	adminSubrouter.HandleFunc("/application/accounts/{id}/system-configs", we.wrapFunc(we.adminApisHandler.updateAccountSystemConfigs, we.auth.admin.Permissions)).Methods("PUT")
	adminSubrouter.HandleFunc("/application/accounts/{id}/verified", we.wrapFunc(we.adminApisHandler.updateAccountVerified, we.auth.admin.Permissions)).Methods("PUT")
	///

	///enc ///
	encSubrouter := subRouter.PathPrefix("/enc").Subrouter()
	encSubrouter.HandleFunc("/test", we.wrapFunc(we.encApisHandler.getTest, nil)).Methods("GET") //Public
	///

	///bbs ///
	bbsSubrouter := subRouter.PathPrefix("/bbs").Subrouter()
	bbsSubrouter.HandleFunc("/service-regs", we.wrapFunc(we.bbsApisHandler.getServiceRegistrations, nil)).Methods("GET") //Public
	bbsSubrouter.HandleFunc("/test", we.wrapFunc(we.bbsApisHandler.getTest, nil)).Methods("GET")                         //Public

	bbsSubrouter.HandleFunc("/service-account/{id}", we.wrapFunc(we.bbsApisHandler.getServiceAccountParams, nil)).Methods("POST") //Public
	bbsSubrouter.HandleFunc("/access-token", we.wrapFunc(we.bbsApisHandler.getServiceAccessToken, nil)).Methods("POST")           //Public
	bbsSubrouter.HandleFunc("/access-tokens", we.wrapFunc(we.bbsApisHandler.getServiceAccessTokens, nil)).Methods("POST")         //Public

	bbsSubrouter.HandleFunc("/accounts", we.wrapFunc(we.bbsApisHandler.getAccounts, we.auth.bbs.Permissions)).Methods("POST")
	bbsSubrouter.HandleFunc("/accounts/count", we.wrapFunc(we.bbsApisHandler.getAccountsCount, we.auth.bbs.Permissions)).Methods("POST")
	///

	///third-party services ///
	tpsSubrouter := subRouter.PathPrefix("/tps").Subrouter()
	tpsSubrouter.HandleFunc("/service-regs", we.wrapFunc(we.tpsApisHandler.getServiceRegistrations, nil)).Methods("GET") //Public
	tpsSubrouter.HandleFunc("/auth-keys", we.wrapFunc(we.tpsApisHandler.getAuthKeys, nil)).Methods("GET")                //Public

	tpsSubrouter.HandleFunc("/service-account/{id}", we.wrapFunc(we.tpsApisHandler.getServiceAccountParams, nil)).Methods("POST") //Public
	tpsSubrouter.HandleFunc("/access-token", we.wrapFunc(we.tpsApisHandler.getServiceAccessToken, nil)).Methods("POST")           //Public
	tpsSubrouter.HandleFunc("/access-tokens", we.wrapFunc(we.tpsApisHandler.getServiceAccessTokens, nil)).Methods("POST")         //Public

	tpsSubrouter.HandleFunc("/accounts", we.wrapFunc(we.tpsApisHandler.getAccounts, we.auth.tps.Permissions)).Methods("POST")
	tpsSubrouter.HandleFunc("/accounts/count", we.wrapFunc(we.tpsApisHandler.getAccountsCount, we.auth.tps.Permissions)).Methods("POST")
	///

	///system ///
	systemSubrouter := subRouter.PathPrefix("/system").Subrouter()

	systemSubrouter.HandleFunc("/auth/app-org-token", we.wrapFunc(we.systemApisHandler.getAppOrgToken, we.auth.system.User)).Methods("GET")

	systemSubrouter.HandleFunc("/organizations", we.wrapFunc(we.systemApisHandler.createOrganization, we.auth.system.Permissions)).Methods("POST")
	systemSubrouter.HandleFunc("/organizations/{id}", we.wrapFunc(we.systemApisHandler.updateOrganization, we.auth.system.Permissions)).Methods("PUT")
	systemSubrouter.HandleFunc("/organizations/{id}", we.wrapFunc(we.systemApisHandler.getOrganization, we.auth.system.Permissions)).Methods("GET")
	systemSubrouter.HandleFunc("/organizations", we.wrapFunc(we.systemApisHandler.getOrganizations, we.auth.system.Permissions)).Methods("GET")

	systemSubrouter.HandleFunc("/applications", we.wrapFunc(we.systemApisHandler.createApplication, we.auth.system.Permissions)).Methods("POST")
	systemSubrouter.HandleFunc("/applications/{id}", we.wrapFunc(we.systemApisHandler.updateApplication, we.auth.system.Permissions)).Methods("PUT")
	systemSubrouter.HandleFunc("/applications/{id}", we.wrapFunc(we.systemApisHandler.getApplication, we.auth.system.Permissions)).Methods("GET")
	systemSubrouter.HandleFunc("/applications", we.wrapFunc(we.systemApisHandler.getApplications, we.auth.system.Permissions)).Methods("GET")

	systemSubrouter.HandleFunc("/app-orgs", we.wrapFunc(we.systemApisHandler.getApplicationOrganizations, we.auth.system.Permissions)).Methods("GET")
	systemSubrouter.HandleFunc("/app-orgs", we.wrapFunc(we.systemApisHandler.createApplicationOrganization, we.auth.system.Permissions)).Methods("POST")
	systemSubrouter.HandleFunc("/app-orgs/{id}", we.wrapFunc(we.systemApisHandler.getApplicationOrganization, we.auth.system.Permissions)).Methods("GET")
	systemSubrouter.HandleFunc("/app-orgs/{id}", we.wrapFunc(we.systemApisHandler.updateApplicationOrganization, we.auth.system.Permissions)).Methods("PUT")

	systemSubrouter.HandleFunc("/permissions", we.wrapFunc(we.systemApisHandler.createPermission, we.auth.system.Permissions)).Methods("POST")
	systemSubrouter.HandleFunc("/permissions", we.wrapFunc(we.systemApisHandler.updatePermission, we.auth.system.Permissions)).Methods("PUT")

	systemSubrouter.HandleFunc("/service-regs", we.wrapFunc(we.systemApisHandler.getServiceRegistrations, we.auth.system.Permissions)).Methods("GET")
	systemSubrouter.HandleFunc("/service-regs", we.wrapFunc(we.systemApisHandler.registerService, we.auth.system.Permissions)).Methods("POST")
	systemSubrouter.HandleFunc("/service-regs", we.wrapFunc(we.systemApisHandler.updateServiceRegistration, we.auth.system.Permissions)).Methods("PUT")
	systemSubrouter.HandleFunc("/service-regs", we.wrapFunc(we.systemApisHandler.deregisterService, we.auth.system.Permissions)).Methods("DELETE")

	systemSubrouter.HandleFunc("/service-accounts", we.wrapFunc(we.systemApisHandler.getServiceAccounts, we.auth.system.Permissions)).Methods("GET")
	systemSubrouter.HandleFunc("/service-accounts", we.wrapFunc(we.systemApisHandler.registerServiceAccount, we.auth.system.Permissions)).Methods("POST")
	systemSubrouter.HandleFunc("/service-accounts", we.wrapFunc(we.systemApisHandler.deregisterServiceAccount, we.auth.system.Permissions)).Methods("DELETE")
	systemSubrouter.HandleFunc("/service-accounts/{id}", we.wrapFunc(we.systemApisHandler.getServiceAccountInstance, we.auth.system.Permissions)).Methods("GET")
	systemSubrouter.HandleFunc("/service-accounts/{id}", we.wrapFunc(we.systemApisHandler.updateServiceAccountInstance, we.auth.system.Permissions)).Methods("PUT")
	systemSubrouter.HandleFunc("/service-accounts/{id}", we.wrapFunc(we.systemApisHandler.deregisterServiceAccountInstance, we.auth.system.Permissions)).Methods("DELETE")
	systemSubrouter.HandleFunc("/service-accounts/{id}/creds", we.wrapFunc(we.systemApisHandler.addServiceAccountCredential, we.auth.system.Permissions)).Methods("POST")
	systemSubrouter.HandleFunc("/service-accounts/{id}/creds", we.wrapFunc(we.systemApisHandler.removeServiceAccountCredential, we.auth.system.Permissions)).Methods("DELETE")

	systemSubrouter.HandleFunc("/api-keys", we.wrapFunc(we.systemApisHandler.getAPIKeys, we.auth.system.Permissions)).Methods("GET")
	systemSubrouter.HandleFunc("/api-keys", we.wrapFunc(we.systemApisHandler.createAPIKey, we.auth.system.Permissions)).Methods("POST")
	systemSubrouter.HandleFunc("/api-keys", we.wrapFunc(we.systemApisHandler.updateAPIKey, we.auth.system.Permissions)).Methods("PUT")
	systemSubrouter.HandleFunc("/api-keys", we.wrapFunc(we.systemApisHandler.deleteAPIKey, we.auth.system.Permissions)).Methods("DELETE")

	systemSubrouter.HandleFunc("/auth-types", we.wrapFunc(we.systemApisHandler.createAuthTypes, we.auth.system.Permissions)).Methods("POST")
	systemSubrouter.HandleFunc("/auth-types", we.wrapFunc(we.systemApisHandler.getAuthTypes, we.auth.system.Permissions)).Methods("GET")
	systemSubrouter.HandleFunc("/auth-types/{id}", we.wrapFunc(we.systemApisHandler.updateAuthTypes, we.auth.system.Permissions)).Methods("PUT")
	///

	var handler http.Handler = router
	if len(we.corsAllowedOrigins) > 0 {
		handler = webauth.SetupCORS(we.corsAllowedOrigins, we.corsAllowedHeaders, router)
	}
	err := http.ListenAndServe(":"+we.port, handler)
	if err != nil {
		we.logger.Fatalf("error on listen and server - %s", err.Error())
	}
}

func (we Adapter) serveResetCredential(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("access-control-allow-origin", "*")
	http.ServeFile(w, r, "./driver/web/ui/reset-credential.html")
}

func (we Adapter) serveWebAuthnTest(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("access-control-allow-origin", "*")
	http.ServeFile(w, r, "./driver/web/ui/webauthn-test.html")
}

func (we Adapter) serveDoc(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("access-control-allow-origin", "*")

	if we.cachedYamlDoc != nil {
		http.ServeContent(w, r, "", time.Now(), bytes.NewReader([]byte(we.cachedYamlDoc)))
	} else {
		http.ServeFile(w, r, "./driver/web/docs/gen/def.yaml")
	}
}

func loadDocsYAML(baseServerURL string, productionServerURL string, testServerURL string, developmentServerURL string) ([]byte, error) {
	data, _ := os.ReadFile("./driver/web/docs/gen/def.yaml")
	// yamlMap := make(map[string]interface{})
	yamlMap := yaml.MapSlice{}
	err := yaml.Unmarshal(data, &yamlMap)
	if err != nil {
		return nil, err
	}

	for index, item := range yamlMap {
		if item.Key == "servers" {
			var serverList []interface{}
			if baseServerURL != "" {
				serverList = []interface{}{yaml.MapSlice{yaml.MapItem{Key: "url", Value: baseServerURL}}}
			} else {
				ok := false
				serverList, ok = item.Value.([]interface{})
				if !ok || len(serverList) != 4 {
					serverList = make([]interface{}, 4)
				}
				if productionServerURL != "" {
					serverList[0] = yaml.MapSlice{
						yaml.MapItem{Key: "url", Value: productionServerURL},
						yaml.MapItem{Key: "description", Value: "Production server"},
					}
				}
				if testServerURL != "" {
					serverList[1] = yaml.MapSlice{
						yaml.MapItem{Key: "url", Value: testServerURL},
						yaml.MapItem{Key: "description", Value: "Test server"},
					}
				}
				if developmentServerURL != "" {
					serverList[2] = yaml.MapSlice{
						yaml.MapItem{Key: "url", Value: developmentServerURL},
						yaml.MapItem{Key: "description", Value: "Development server"},
					}
				}
				serverList[3] = yaml.MapSlice{
					yaml.MapItem{Key: "url", Value: "http://localhost/core"},
					yaml.MapItem{Key: "description", Value: "Local server"},
				}
			}

			item.Value = serverList
			yamlMap[index] = item
			break
		}
	}

	yamlDoc, err := yaml.Marshal(&yamlMap)
	if err != nil {
		return nil, err
	}

	return yamlDoc, nil
}

func (we Adapter) serveDocUI() http.Handler {
	url := fmt.Sprintf("%s/doc", we.host)
	return httpSwagger.Handler(httpSwagger.URL(url))
}

func (we Adapter) wrapFunc(handler handlerFunc, authorization tokenauth.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		logObj := we.logger.NewRequestLog(req)

		logObj.RequestReceived()

		var err error

		//1. validate request
		var response logs.HTTPResponse
		var requestValidationInput *openapi3filter.RequestValidationInput
		if we.env == "local" {
			requestValidationInput, err = we.validateRequest(req)
			if err != nil {
				response = logObj.HTTPResponseErrorAction(logutils.ActionValidate, logutils.TypeRequest, nil, err, http.StatusBadRequest, true)
				we.completeResponse(w, response, logObj)
				return
			}
		}

		//2. process it
		if authorization != nil {
			responseStatus, claims, err := authorization.Check(req)
			if err != nil {
				response = logObj.HTTPResponseErrorAction(logutils.ActionValidate, logutils.TypeRequest, nil, err, responseStatus, true)
				we.completeResponse(w, response, logObj)
				return
			}

			logObj.SetContext("account_id", claims.Subject)
			response = handler(logObj, req, claims)
		} else {
			response = handler(logObj, req, nil)
		}

		//3. validate the response
		if we.env == "local" {
			err = we.validateResponse(requestValidationInput, response)
			if err != nil {
				response = logObj.HTTPResponseErrorAction(logutils.ActionValidate, logutils.TypeResponse, &logutils.FieldArgs{"code": response.ResponseCode, "headers": response.Headers, "body": string(response.Body)}, err, http.StatusInternalServerError, true)
			}
		}

		//4. complete response
		we.completeResponse(w, response, logObj)
	}
}

func (we Adapter) uiWrapFunc(handler handlerFunc, authorization tokenauth.Handler) http.HandlerFunc {
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
		var response logs.HTTPResponse
		if authorization != nil {
			_, claims, err := authorization.Check(req)
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
		response := l.HTTPResponseErrorAction(logutils.ActionLoad, "page template", nil, err, http.StatusInternalServerError, true)
		we.completeResponse(w, response, l)
		return
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
	options := &openapi3filter.Options{AuthenticationFunc: dummyAuthFunc, ExcludeReadOnlyValidations: true}
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

func (we Adapter) validateResponse(requestValidationInput *openapi3filter.RequestValidationInput, response logs.HTTPResponse) error {
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

func (we Adapter) completeResponse(w http.ResponseWriter, response logs.HTTPResponse, l *logs.Log) {
	//1. return response
	l.SendHTTPResponse(w, response)

	//2. print
	l.RequestComplete()
}

// NewWebAdapter creates new WebAdapter instance
func NewWebAdapter(env string, serviceRegManager *authservice.ServiceRegManager, port string, coreAPIs *core.APIs, host string, corsAllowedOrigins []string,
	corsAllowedHeaders []string, baseServerURL string, prodServerURL string, testServerURL string, devServerURL string, logger *logs.Logger) Adapter {
	//openAPI doc
	loader := &openapi3.Loader{Context: context.Background(), IsExternalRefsAllowed: true}
	// doc, err := loader.LoadFromFile("driver/web/docs/gen/def.yaml")
	// if err != nil {
	// 	logger.Fatalf("error on openapi3 load from file - %s", err.Error())
	// }

	yamlDoc, err := loadDocsYAML(baseServerURL, prodServerURL, testServerURL, devServerURL)
	if err != nil {
		logger.Fatalf("error parsing docs yaml - %s", err.Error())
	}
	doc, err := loader.LoadFromData(yamlDoc)
	if err != nil {
		logger.Fatalf("error loading docs yaml - %s", err.Error())
	}
	err = doc.Validate(loader.Context, openapi3.EnableExamplesValidation())
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

	auth, err := NewAuth(serviceRegManager)
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
	return Adapter{env: env, port: port, productionServerURL: prodServerURL, testServerURL: testServerURL, developmentServerURL: devServerURL, cachedYamlDoc: yamlDoc,
		openAPIRouter: openAPIRouter, host: host, auth: auth, logger: logger, defaultApisHandler: defaultApisHandler, servicesApisHandler: servicesApisHandler, adminApisHandler: adminApisHandler,
		encApisHandler: encApisHandler, bbsApisHandler: bbsApisHandler, tpsApisHandler: tpsApisHandler, systemApisHandler: systemApisHandler, coreAPIs: coreAPIs,
		corsAllowedOrigins: corsAllowedOrigins, corsAllowedHeaders: corsAllowedHeaders}
}

// AppListener implements core.ApplicationListener interface
type AppListener struct {
	adapter *Adapter
}
