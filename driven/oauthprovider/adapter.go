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

package oauthprovider

import (
	"net/http"
	"strings"

	"github.com/rokwire/core-auth-library-go/v2/authutils"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
)

// Adapter implements the OAuthProvider interface
type Adapter struct{}

// LoadToken loads an access token from an external OAuth provider
func (a *Adapter) LoadToken(config OAuthConfig, creds string, params string, refresh bool) (OAuthToken, map[string]interface{}, error) {
	request, responseParams, err := config.BuildNewTokenRequest(creds, params, refresh)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionCreate, "token request", nil, err)
	}
	if refresh && request == nil {
		return nil, nil, nil
	}
	if responseParams == nil {
		responseParams = map[string]interface{}{}
	}

	req, err := http.NewRequest(request.Method, request.URL, strings.NewReader(request.Body))
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeRequest, nil, err)
	}
	for k, v := range request.Headers {
		req.Header.Set(k, v)
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionSend, logutils.TypeRequest, nil, err)
	}

	body, err := authutils.ReadResponseBody(resp)
	if err != nil {
		return nil, nil, errors.WrapErrorAction(logutils.ActionRead, logutils.TypeResponse, nil, err)
	}

	return config.ParseTokenResponse(body, responseParams)
}

// LoadUserInfo loads user information from an external OAuth provider
func (a *Adapter) LoadUserInfo(config OAuthConfig, token OAuthToken) ([]byte, error) {
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, config.GetUserInfoURL(), nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeRequest, nil, err)
	}
	req.Header.Set("Authorization", token.GetAuthorizationHeader())

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionSend, logutils.TypeRequest, nil, err)
	}

	body, err := authutils.ReadResponseBody(resp)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRead, logutils.TypeResponse, nil, err)
	}

	return body, nil
}

// NewOAuthProviderAdapter creates a new oauth provider adapter instance
func NewOAuthProviderAdapter() *Adapter {
	return &Adapter{}
}

// OAuthConfig represents a configuration for communication with an external OAuth provider
type OAuthConfig interface {
	GetAuthorizeURL() string
	GetTokenURL() string
	GetUserInfoURL() string

	GetAuthorizationCode(creds string, params string) (string, error)
	BuildNewTokenRequest(creds string, params string, refresh bool) (*OAuthRequest, map[string]interface{}, error)
	ParseTokenResponse(response []byte, params map[string]interface{}) (OAuthToken, map[string]interface{}, error)
	BuildLoginURLResponse(redirectURI string) (string, map[string]interface{}, error)

	// GetResponseParams(params string) (map[string]string, error)

	CheckIDToken(token OAuthToken) (string, error)
	CheckSubject(tokenSubject string, userSubject string) bool
}

// OAuthToken represents an access token entity received from an external OAuth provider
type OAuthToken interface {
	GetAuthorizationHeader() string
	GetResponseParams() map[string]interface{}
	GetIDToken() string
}

// OAuthRequest represents a request to be sent by an OAuth provider
type OAuthRequest struct {
	Method  string
	URL     string
	Body    string
	Headers map[string]string
}
