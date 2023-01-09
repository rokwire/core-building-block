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

package model

import (
	"fmt"
	"time"

	"github.com/rokwire/logging-library-go/errors"
	"github.com/rokwire/logging-library-go/logutils"
)

const (
	// TypeConfig configs type
	TypeConfig logutils.MessageDataType = "config"
	// TypeEnvConfigData env configs type
	TypeEnvConfigData logutils.MessageDataType = "env config data"
	//TypeOrganizationConfig ...
	TypeOrganizationConfig logutils.MessageDataType = "org config"

	// ConfigIDEnv is the Config ID for EnvConfigData
	ConfigIDEnv string = "env"
)

// Config contains generic configs
type Config struct {
	ID          string      `json:"id" bson:"_id"`
	Data        interface{} `json:"data" bson:"data"`
	DateCreated time.Time   `json:"date_created" bson:"date_created"`
	DateUpdated *time.Time  `json:"date_updated" bson:"date_updated"`
}

// DataAsEnvConfig returns the config Data as an EnvConfigData if the cast succeeds
func (c *Config) DataAsEnvConfig() (*EnvConfigData, error) {
	data, ok := c.Data.(EnvConfigData)
	if !ok {
		return nil, errors.ErrorData(logutils.StatusInvalid, TypeEnvConfigData, nil)
	}
	return &data, nil
}

// EnvConfigData contains environment configs for this service
type EnvConfigData struct {
	AllowLegacyRefresh *bool `json:"allow_legacy_refresh,omitempty" bson:"allow_legacy_refresh,omitempty"`
}

// OrganizationConfig represents configuration for an organization
type OrganizationConfig struct {
	ID      string `bson:"id"`
	Setting string `bson:"setting"`
	//???
	Domains []string `bson:"domains"` //some organizations have their own users so that we need to associate a user with an organization

	Custom interface{} `bson:"custom"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

func (cc OrganizationConfig) String() string {
	return fmt.Sprintf("[ID:%s\tSetting:%s\tDomains:%s\tCustom:%v]", cc.ID, cc.Setting, cc.Domains, cc.Custom)
}
