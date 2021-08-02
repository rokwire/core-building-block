package storage

import (
	"core-building-block/core/model"
	"time"
)

type organization struct {
	ID               string   `bson:"_id"`
	Name             string   `bson:"name"`
	Type             string   `bson:"type"`
	RequiresOwnLogin bool     `bson:"requires_own_login"`
	LoginTypes       []string `bson:"login_types"`

	Config organizationConfig `bson:"config"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type organizationConfig struct {
	ID      string   `bson:"id"`
	Domains []string `bson:"domains"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type rawMembership struct {
	ID     string `bson:"_id"`
	UserID string `bson:"user_id"`

	OrgID       string                 `bson:"organization_id"`
	OrgUserData map[string]interface{} `bson:"org_user_data"`

	Permissions []string `bson:"permissions"`
	Roles       []string `bson:"roles"`
	Groups      []string `bson:"groups"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type userMembership struct {
	ID string `bson:"_id"`

	OrgID       string                 `bson:"organization_id"`
	OrgUserData map[string]interface{} `bson:"org_user_data"`

	Permissions []model.OrganizationPermission `bson:"permissions"`
	Roles       []model.OrganizationRole       `bson:"roles"`
	Groups      []model.OrganizationGroup      `bson:"groups"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type application struct {
	ID       string   `bson:"_id"`
	Name     string   `bson:"name"`
	Versions []string `bson:"versions"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}
