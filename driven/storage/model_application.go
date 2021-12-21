package storage

import (
	"core-building-block/core/model"
	"time"
)

type application struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`

	MultiTenant      bool `bson:"multi_tenant"`
	RequiresOwnUsers bool `bson:"requires_own_users"`
	Admin            bool `bson:"admin"`

	MaxLoginSessionDuration *int `bson:"max_login_session_duration,omitempty"`

	Types []applicationType `bson:"types"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type applicationType struct {
	ID         string    `bson:"id"`
	Identifier string    `bson:"identifier"`
	Name       string    `bson:"name"`
	Versions   []version `bson:"versions"`
}

type version struct {
	ID              string               `json:"id" bson:"_id"`
	VersionNumbers  model.VersionNumbers `json:"version_numbers" bson:"version_numbers"`
	ApplicationType applicationType      `json:"app_type" bson:"app_type"`

	DateCreated time.Time  `json:"date_created" bson:"date_created"`
	DateUpdated *time.Time `json:"date_updated" bson:"date_updated"`
}

type applicationConfig struct {
	ID        string  `json:"id" bson:"_id"`
	AppTypeID string  `json:"app_type_id" bson:"app_type_id"`
	Version   version `json:"version" bson:"version"`
	AppOrgID  *string `bson:"app_org_id"`

	Data map[string]interface{} `json:"data" bson:"data"`

	DateCreated time.Time  `json:"date_created" bson:"date_created"`
	DateUpdated *time.Time `json:"date_updated" bson:"date_updated"`
}

type organization struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`
	Type string `bson:"type"`

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

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type appOrgGroup struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`

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

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}
