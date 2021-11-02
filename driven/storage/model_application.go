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

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}
type applicationGroup struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`

	AppID string `bson:"app_id"`

	Permissions []model.Permission `bson:"permissions"`
	Roles       []applicationRole  `bson:"roles"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type applicationRole struct {
	ID          string `bson:"_id"`
	Name        string `bson:"name"`
	Description string `bson:"description"`

	AppID string `bson:"app_id"`

	Permissions []model.Permission `bson:"permissions"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}
