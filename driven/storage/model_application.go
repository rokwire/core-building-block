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

	Types []applicationType `bson:"types"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type applicationType struct {
	ID         string   `bson:"id"`
	Identifier string   `bson:"identifier"`
	Name       string   `bson:"name"`
	Versions   []string `bson:"versions"`
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

	LoginsSessionsSetting model.LoginsSessionsSetting `bson:"logins_sessions_settings"`

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

type servicereg struct {
	ServiceID string `json:"service_id" bson:"service_id" validate:"required"`
	Host      string `json:"host" bson:"host" validate:"required"`
}
