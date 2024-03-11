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
	"time"

	"core-building-block/core/model"
)

// deprecated
type account struct {
	ID string `bson:"_id"`

	AppOrgID string `bson:"app_org_id,omitempty"`

	Permissions []model.Permission `bson:"permissions,omitempty"`
	Roles       []accountRole      `bson:"roles,omitempty"`
	Groups      []accountGroup     `bson:"groups,omitempty"`
	Scopes      []string           `bson:"scopes,omitempty"`

	AuthTypes []accountAuthType `bson:"auth_types,omitempty"`

	MFATypes []mfaType `bson:"mfa_types,omitempty"`

	Username      string                 `bson:"username"`
	ExternalIDs   map[string]string      `bson:"external_ids"`
	Preferences   map[string]interface{} `bson:"preferences"`
	SystemConfigs map[string]interface{} `bson:"system_configs"`
	Profile       profile                `bson:"profile"`

	Devices []userDevice `bson:"devices,omitempty"`

	Anonymous bool          `bson:"anonymous"`
	Privacy   model.Privacy `bson:"privacy"`
	Verified  bool          `bson:"verified"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`

	IsFollowing bool `bson:"is_following"`

	LastLoginDate           *time.Time `bson:"last_login_date"`
	LastAccessTokenDate     *time.Time `bson:"last_access_token_date"`
	MostRecentClientVersion *string    `bson:"most_recent_client_version"`

	Migrated *bool `bson:"migrated_2"`
}

type tenantAccount struct {
	ID string `bson:"_id"`

	OrgID              string             `bson:"org_id"`
	OrgAppsMemberships []orgAppMembership `bson:"org_apps_memberships"`

	Scopes []string `bson:"scopes,omitempty"`

	AuthTypes []accountAuthType `bson:"auth_types,omitempty"`

	MFATypes []mfaType `bson:"mfa_types,omitempty"`

	Username    string            `bson:"username"`
	ExternalIDs map[string]string `bson:"external_ids"`

	SystemConfigs map[string]interface{} `bson:"system_configs"`
	Profile       profile                `bson:"profile"`

	Devices []userDevice `bson:"devices,omitempty"`

	Anonymous bool          `bson:"anonymous"`
	Privacy   model.Privacy `bson:"privacy"`
	Verified  *bool         `bson:"verified,omitempty"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
	DateDeleted *time.Time `bson:"date_deleted"`

	IsFollowing bool `bson:"is_following"`

	LastLoginDate       *time.Time `bson:"last_login_date"`
	LastAccessTokenDate *time.Time `bson:"last_access_token_date"`
}

type orgAppMembership struct {
	ID       string `bson:"id,omitempty"`
	AppOrgID string `bson:"app_org_id,omitempty"`

	Permissions []model.Permission `bson:"permissions,omitempty"`
	Roles       []accountRole      `bson:"roles,omitempty"`
	Groups      []accountGroup     `bson:"groups,omitempty"`

	Preferences map[string]interface{} `bson:"preferences"`

	MostRecentClientVersion *string    `bson:"most_recent_client_version"`
	DateDeleted             *time.Time `bson:"date_deleted,omitempty"`
}

type accountRole struct {
	Role     appOrgRole `bson:"role"`
	Active   bool       `bson:"active"`
	AdminSet bool       `bson:"admin_set"`
}

type accountGroup struct {
	Group    appOrgGroup `bson:"group"`
	Active   bool        `bson:"active"`
	AdminSet bool        `bson:"admin_set"`
}

type accountAuthType struct {
	ID           string                 `bson:"id"`
	AuthTypeID   string                 `bson:"auth_type_id"`
	AuthTypeCode string                 `bson:"auth_type_code"`
	Identifier   string                 `bson:"identifier"`
	Params       map[string]interface{} `bson:"params"`
	CredentialID *string                `bson:"credential_id"`
	Active       bool                   `bson:"active"`
	Unverified   bool                   `bson:"unverified"`
	Linked       bool                   `bson:"linked"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type profile struct {
	ID string `bson:"id"`

	PhotoURL  string `bson:"photo_url"`
	FirstName string `bson:"first_name"`
	LastName  string `bson:"last_name"`
	Email     string `bson:"email"`
	Phone     string `bson:"phone"`
	BirthYear int16  `bson:"birth_year"`
	Address   string `bson:"address"`
	ZipCode   string `bson:"zip_code"`
	State     string `bson:"state"`
	Country   string `bson:"country"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`

	UnstructuredProperties map[string]interface{} `bson:"unstructured_properties"`
}

type userDevice struct {
	ID string `bson:"_id"`

	DeviceID *string `bson:"device_id"`

	Type string `bson:"type"`
	OS   string `bson:"os"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type device struct {
	ID string `bson:"_id"`

	DeviceID *string `bson:"device_id"`
	Account  string  `bson:"account_id"`

	Type string `bson:"type"`
	OS   string `bson:"os"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type credential struct {
	ID string `bson:"_id"`

	AuthTypeID        string                 `bson:"auth_type_id"`
	AccountsAuthTypes []string               `bson:"account_auth_types"`
	Verified          bool                   `bson:"verified"`
	Value             map[string]interface{} `bson:"value"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type mfaType struct {
	ID   string `bson:"id"`
	Type string `bson:"type"`

	Verified bool                   `bson:"verified"`
	Params   map[string]interface{} `bson:"params"` //mfa type params

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type follow struct {
	ID string `bson:"_id"`

	AppOrgID string `bson:"app_org_id,omitempty"`

	FollowerID  string `bson:"follower_id"`
	FollowingID string `bson:"following_id"`
}
