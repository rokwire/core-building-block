package storage

import (
	"core-building-block/core/model"
	"time"
)

type application struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`

	MultiTenant      bool `bson:"multi_tenant"`
	SharedIdentities bool `bson:"shared_identities"`
	Admin            bool `bson:"admin"`

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
	Accounts    []account          `bson:"accounts"`

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
