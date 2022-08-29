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
	"encoding/json"
	"net/http"

	"github.com/rokwire/core-auth-library-go/v2/authutils"
	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
	"gopkg.in/go-playground/validator.v9"
)

// Adapter implements the OAuthProvider interface
type Adapter struct{}

// LoadToken loads an access token from an external OAuth provider
func (a *Adapter) LoadToken(config OAuthConfig, creds string, params string, refresh bool, result OAuthToken) error {
	req, err := config.BuildNewTokenRequest(creds, params, refresh)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionCreate, "token request", nil, err)
	}
	if refresh && req == nil {
		return nil
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionSend, logutils.TypeRequest, nil, err)
	}

	body, err := authutils.ReadResponseBody(resp)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionRead, logutils.TypeResponse, nil, err)
	}

	err = json.Unmarshal(body, result)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionUnmarshal, logutils.TypeToken, nil, err)
	}
	validate := validator.New()
	err = validate.Struct(result)
	if err != nil {
		return errors.WrapErrorAction(logutils.ActionValidate, logutils.TypeToken, nil, err)
	}

	return nil
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
	EmptyToken() OAuthToken
	GetAuthorizeURL() string
	GetTokenURL() string
	GetUserInfoURL() string

	GetAuthorizationCode(creds string, params string) (string, error)
	BuildNewTokenRequest(creds string, params string, refresh bool) (*http.Request, error)
	CheckIDToken(token OAuthToken) (string, error)
	CheckSubject(tokenSubject string, userSubject string) bool
	BuildLoginURLResponse() (string, map[string]interface{}, error)
}

// OAuthToken represents an access token entity received from an external OAuth provider
type OAuthToken interface {
	GetAuthorizationHeader() string
	GetResponse() map[string]interface{}
	GetIDToken() string
}
