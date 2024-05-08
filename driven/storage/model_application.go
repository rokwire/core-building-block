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

package storage

import (
	"core-building-block/core/model"
	"time"
)

type application struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`

	MultiTenant bool   `bson:"multi_tenant"`
	Admin       bool   `bson:"admin"`
	Code        string `bson:"code"`

	Types []applicationType `bson:"types"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type applicationType struct {
	ID         string    `bson:"id"`
	Identifier string    `bson:"identifier"`
	Name       string    `bson:"name"`
	Versions   []version `bson:"versions"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type version struct {
	ID             string               `bson:"_id"`
	VersionNumbers model.VersionNumbers `bson:"version_numbers"`
	AppTypeID      string               `bson:"app_type_id"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type applicationConfig struct {
	ID        string  `bson:"_id"`
	AppTypeID string  `bson:"app_type_id"`
	Version   version `bson:"version"`
	AppOrgID  *string `bson:"app_org_id"`

	Data map[string]interface{} `bson:"data"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type organization struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`
	Type string `bson:"type"`

	System bool `bson:"system"`

	Config model.OrganizationConfig `bson:"config"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type applicationOrganization struct {
	ID string `bson:"_id"`

	AppID string `bson:"app_id"`
	OrgID string `bson:"org_id"`

	ServicesIDs []string `bson:"services_ids"`

	IdentityProvidersSettings []model.IdentityProviderSetting `bson:"identity_providers_settings"`

	SupportedAuthTypes []model.AuthTypesSupport `bson:"supported_auth_types"`

	LoginsSessionsSetting model.LoginsSessionsSetting `bson:"logins_sessions_settings"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type appOrgGroup struct {
	ID          string `bson:"_id"`
	Name        string `bson:"name"`
	Description string `bson:"description"`

	System bool `bson:"system"`

	AppOrgID string `bson:"app_org_id"`

	Permissions []model.Permission `bson:"permissions"`
	Roles       []appOrgRole       `bson:"roles"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type appOrgRole struct {
	ID          string `bson:"_id"`
	Name        string `bson:"name"`
	Description string `bson:"description"`

	System bool `bson:"system"`

	AppOrgID string `bson:"app_org_id"`

	Permissions []model.Permission `bson:"permissions"`
	Scopes      []string           `bson:"scopes"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}
