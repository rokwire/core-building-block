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

package identitybb

import (
	"core-building-block/core/model"
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logs"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

// Adapter implements the IdentityBuildingBlock interface
type Adapter struct {
}

// GetUserProfile gets user profile info for the provided user credentials
func (a *Adapter) GetUserProfile(baseURL string, externalUser model.ExternalSystemUser, externalAccessToken string, l *logs.Log) (*model.Profile, error) {
	if baseURL == "" || externalAccessToken == "" {
		return nil, errors.ErrorData(logutils.StatusMissing, "base url", nil)
	}

	if externalAccessToken == "" {
		return nil, errors.ErrorData(logutils.StatusMissing, "access token", nil)
	}

	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, baseURL+"/StudentSummary/"+externalUser.Identifier+"/"+externalUser.FirstName+"/"+externalUser.LastName, nil)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionCreate, logutils.TypeRequest, nil, err)
	}

	req.Header.Set("access_token", externalAccessToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionSend, logutils.TypeRequest, nil, err)
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionRead, logutils.TypeResponse, nil, err)
	}
	if resp.StatusCode != 200 {
		return nil, errors.ErrorData(logutils.StatusInvalid, logutils.TypeResponse, &logutils.FieldArgs{"status_code": resp.StatusCode, "error": string(body)})
	}
	if len(body) == 0 {
		return nil, errors.ErrorData(logutils.StatusMissing, logutils.TypeResponseBody, nil)
	}

	var profileData map[string]interface{}
	err = json.Unmarshal(body, &profileData)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, logutils.TypeResponseBody, nil, err)
	}

	profile := model.ProfileFromMap(profileData)

	return &profile, nil
}

// NewIdentityBBAdapter creates a new identity building block adapter instance
func NewIdentityBBAdapter() *Adapter {
	return &Adapter{}
}
