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
	"encoding/json"

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

func configToDef(item model.Config) (*Def.Config, error) {
	var dateUpdated *string
	dateCreated := utils.FormatTime(&item.DateCreated)
	if item.DateUpdated != nil {
		formatted := utils.FormatTime(item.DateUpdated)
		dateUpdated = &formatted
	}

	var configData Def.Config_Data
	if item.Data != nil {
		configBytes, err := json.Marshal(item.Data)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionMarshal, model.TypeConfig, nil, err)
		}

		err = json.Unmarshal(configBytes, &configData)
		if err != nil {
			return nil, errors.WrapErrorAction(logutils.ActionUnmarshal, model.TypeConfig, nil, err)
		}
	}

	return &Def.Config{Id: &item.ID, Type: item.Type, AppId: item.AppID, OrgId: item.OrgID, System: item.System, Data: configData,
		DateCreated: &dateCreated, DateUpdated: dateUpdated}, nil
}

func configFromDef(item Def.Config) model.Config {
	return model.Config{Type: item.Type, AppID: item.AppId, OrgID: item.OrgId, System: item.System, Data: item.Data}
}
