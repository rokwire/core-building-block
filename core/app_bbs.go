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

package core

import (
	"core-building-block/core/model"

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

func (app *application) bbsGetDeletedOrgAppMemberships(appID string, orgID string, serviceID string) (map[model.AppOrgPair][]model.DeletedOrgAppMembership, error) {
	memberships, err := app.storage.FindDeletedOrgAppMemberships(appID, orgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeDeletedOrgAppMembership, nil, err)
	}

	// group the deleted memberships by AppOrgPairs
	deletedMemberships := make(map[model.AppOrgPair][]model.DeletedOrgAppMembership)
	for _, membership := range memberships {
		appOrgPair := model.AppOrgPair{AppID: membership.AppOrg.Application.ID, OrgID: membership.AppOrg.Organization.ID}
		if _, exists := deletedMemberships[appOrgPair]; !exists {
			deletedMemberships[appOrgPair] = make([]model.DeletedOrgAppMembership, 0)
		}
		deletedMemberships[appOrgPair] = append(deletedMemberships[appOrgPair], membership)
	}

	return deletedMemberships, nil
}

func (app *application) bbsGetTest() string {
	return "BBs - test"
}
