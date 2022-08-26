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

	"github.com/rokwire/logging-library-go/logutils"
)

const (
	//TypeGlobalConfig ...
	TypeGlobalConfig logutils.MessageDataType = "global config"
	//TypeOrganizationConfig ...
	TypeOrganizationConfig logutils.MessageDataType = "org config"
)

// GlobalConfig represents global config for the system
type GlobalConfig struct {
	Setting string
}

func (gc GlobalConfig) String() string {
	return fmt.Sprintf("[setting:%s]", gc.Setting)
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
	return fmt.Sprintf("[ID:%s\tSetting:%s\tDomains:%s\tCustom:%s]", cc.ID, cc.Setting, cc.Domains, cc.Custom)
}
