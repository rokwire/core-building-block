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

package auth

import (
	"core-building-block/core/model"

	"github.com/rokwire/rokwire-building-block-sdk-go/utils/errors"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logs"
	"github.com/rokwire/rokwire-building-block-sdk-go/utils/logging/logutils"
)

const (
	//AuthTypeSaml saml auth type
	AuthTypeSaml string = "saml"
)

// SAML implementation of authType
type samlAuthImpl struct {
	auth     *Auth
	authType string
}

func (a *samlAuthImpl) externalLogin(authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, creds string, params string, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, string, error) {
	return nil, nil, "", nil
}

func (a *samlAuthImpl) getLoginURL(authType model.AuthType, appType model.ApplicationType, redirectURI string, l *logs.Log) (string, map[string]interface{}, error) {
	return "", nil, errors.ErrorData(logutils.StatusInvalid, "operation", logutils.StringArgs(a.authType))
}

func (a *samlAuthImpl) refresh(params map[string]interface{}, authType model.AuthType, appType model.ApplicationType, appOrg model.ApplicationOrganization, l *logs.Log) (*model.ExternalSystemUser, map[string]interface{}, string, error) {
	return nil, nil, "", nil
}

// initSamlAuth initializes and registers a new SAML auth instance
func initSamlAuth(auth *Auth) (*samlAuthImpl, error) {
	saml := &samlAuthImpl{auth: auth, authType: AuthTypeSaml}

	err := auth.registerExternalAuthType(saml.authType, saml)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRegister, typeExternalAuthType, nil, err)
	}

	return saml, nil
}
