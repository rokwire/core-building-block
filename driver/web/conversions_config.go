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
	"core-building-block/core/model"
	Def "core-building-block/driver/web/docs/gen"
	"core-building-block/utils"

	"github.com/rokwire/core-auth-library-go/v2/authutils"
)

func configListToDef(items []model.Config) []Def.Config {
	result := make([]Def.Config, len(items))
	for i, item := range items {
		result[i] = configToDef(item)
	}
	return result
}

func configToDef(item model.Config) Def.Config {
	var dateUpdated *string
	dateCreated := utils.FormatTime(&item.DateCreated)
	if item.DateUpdated != nil {
		formatted := utils.FormatTime(item.DateUpdated)
		dateUpdated = &formatted
	}

	return Def.Config{Id: &item.ID, Type: item.Type, AppId: &item.AppID, OrgId: &item.OrgID, System: item.System, Data: item.Data,
		DateCreated: &dateCreated, DateUpdated: dateUpdated}
}

func configFromDef(item Def.Config, appID string, orgID string) model.Config {
	if item.AllApps != nil && *item.AllApps {
		appID = authutils.AllApps
	}
	if item.AllOrgs != nil && *item.AllOrgs {
		orgID = authutils.AllOrgs
	}
	return model.Config{Type: item.Type, AppID: appID, OrgID: orgID, System: item.System, Data: item.Data}
}
