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

func (app *application) bbsGetDeletedOrgAppMemberships(appID string, orgID string) (map[string][]model.AppOrgPair, error) {
	accounts, err := app.storage.FindDeletedAccounts(appID, orgID)
	if err != nil {
		return nil, errors.WrapErrorAction(logutils.ActionFind, model.TypeAccount, nil, err)
	}
	if len(accounts) == 0 {
		return nil, nil
	}

	deletedAccounts := make(map[string][]model.AppOrgPair)
	for _, account := range accounts {
		for _, membership := range account.OrgAppsMemberships {
			if membership.IsDeleted() {
				if _, exists := deletedAccounts[account.ID]; !exists {
					deletedAccounts[account.ID] = make([]model.AppOrgPair, 0)
				}
				deletedAccounts[account.ID] = append(deletedAccounts[account.ID], model.AppOrgPair{AppID: membership.AppOrg.Application.ID, OrgID: account.OrgID})
			}
		}
	}

	return deletedAccounts, nil
}

func (app *application) bbsGetTest() string {
	return "BBs - test"
}
