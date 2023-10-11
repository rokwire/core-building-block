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

	"github.com/rokwire/logging-library-go/v2/errors"
	"github.com/rokwire/logging-library-go/v2/logutils"
)

const (
	// TypeConfig configs type
	TypeConfig logutils.MessageDataType = "config"
	// TypeConfigData config data type
	TypeConfigData logutils.MessageDataType = "config data"
	// TypeEnvConfigData env configs type
	TypeEnvConfigData logutils.MessageDataType = "env config data"
	// TypeAuthConfigData auth configs type
	TypeAuthConfigData logutils.MessageDataType = "auth config data"
	//TypeOrganizationConfig ...
	TypeOrganizationConfig logutils.MessageDataType = "org config"

	// ConfigTypeEnv is the Config type for EnvConfigData
	ConfigTypeEnv string = "env"
	// ConfigTypeAuth is the Config type for AuthConfigData
	ConfigTypeAuth string = "auth"
)

// Config contains generic configs
type Config struct {
	ID          string      `bson:"_id"`
	Type        string      `bson:"type"`
	AppID       string      `bson:"app_id"`
	OrgID       string      `bson:"org_id"`
	System      bool        `bson:"system"`
	Data        interface{} `bson:"data"`
	DateCreated time.Time   `bson:"date_created"`
	DateUpdated *time.Time  `bson:"date_updated"`
}

// EnvConfigData contains environment configs for this service
type EnvConfigData struct {
	CORSAllowedOrigins []string `json:"cors_allowed_origins" bson:"cors_allowed_origins"`
	CORSAllowedHeaders []string `json:"cors_allowed_headers" bson:"cors_allowed_headers"`
}

// AuthConfigData contains auth configs for this service
type AuthConfigData struct {
	EmailShouldVerify   *bool `json:"email_should_verify" bson:"email_should_verify"`
	EmailVerifyWaitTime *int  `json:"email_verify_wait_time" bson:"email_verify_wait_time"`
	EmailVerifyExpiry   *int  `json:"email_verify_expiry" bson:"email_verify_expiry"`
}

// GetConfigData returns a pointer to the given config's Data as the given type T
func GetConfigData[T ConfigData](c Config) (*T, error) {
	if data, ok := c.Data.(T); ok {
		return &data, nil
	}
	return nil, errors.ErrorData(logutils.StatusInvalid, TypeConfigData, &logutils.FieldArgs{"type": c.Type})
}

// ConfigData represents any set of data that may be stored in a config
type ConfigData interface {
	EnvConfigData | AuthConfigData | map[string]interface{}
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
