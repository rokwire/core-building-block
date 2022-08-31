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
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
	"encoding/json"
	"net/http"

	"github.com/rokwire/core-auth-library-go/v2/sigauth"
	"github.com/rokwire/core-auth-library-go/v2/tokenauth"
	"github.com/rokwire/logging-library-go/logs"
	"github.com/rokwire/logging-library-go/logutils"
)

// DefaultApisHandler handles default APIs implementation - version etc
type DefaultApisHandler struct {
	coreAPIs *core.APIs
}

// getVersion gives the service version
func (h DefaultApisHandler) getVersion(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	version := h.coreAPIs.GetVersion()

	return l.HttpResponseSuccessMessage(version)
}

// getOpenIDConfiguration gives the OpenID Connect Discovery page
func (h DefaultApisHandler) getOpenIDConfiguration(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	discovery := Def.OIDCDiscovery{Issuer: h.coreAPIs.Auth.GetHost(), JwksUri: h.coreAPIs.Auth.GetHost() + "/tps/auth-keys"}

	data, err := json.Marshal(discovery)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionMarshal, "openid configs", nil, err, http.StatusInternalServerError, false)
	}

	return l.HttpResponseSuccessJSON(data)
}

func (h DefaultApisHandler) handleWebhookConfigChange(l *logs.Log, r *http.Request, claims *tokenauth.Claims) logs.HttpResponse {
	req, err := sigauth.ParseHTTPRequest(r)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionParse, "sigauth http request", nil, err, http.StatusInternalServerError, false)
	}

	err = h.coreAPIs.Default.ProcessVCSAppConfigWebhook(req, l)
	if err != nil {
		return l.HttpResponseErrorAction(logutils.ActionUpdate, model.TypeApplicationConfigWebhook, nil, err, http.StatusInternalServerError, true)
	}

	return l.HttpResponseSuccess()
}

// NewDefaultApisHandler creates new rest services Handler instance
func NewDefaultApisHandler(coreAPIs *core.APIs) DefaultApisHandler {
	return DefaultApisHandler{coreAPIs: coreAPIs}
}
