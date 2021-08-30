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

	Config model.OrganizationConfig `bson:"config"`

	Applications []string `bson:"applications"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type organizationGroup struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`

	OrgID string `bson:"org_id"`

	Permissions []organizationPermission `bson:"permissions"`
	Roles       []organizationRole       `bson:"roles"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type organizationRole struct {
	ID          string `bson:"_id"`
	Name        string `bson:"name"`
	Description string `bson:"description"`

	OrgID string `bson:"org_id"`

	Permissions []organizationPermission `bson:"permissions"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type organizationPermission struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`

	OrgID string `bson:"org_id"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type organizationMembership struct {
	ID     string `bson:"_id"`
	UserID string `bson:"user_id"`

	OrgID       string                 `bson:"org_id"`
	OrgUserData map[string]interface{} `bson:"org_user_data"`

	Permissions []string `bson:"permissions"`
	Roles       []string `bson:"roles"`
	Groups      []string `bson:"groups"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type application struct {
	ID       string   `bson:"_id"`
	Name     string   `bson:"name"`     //safer community mobile, safer community web, uuic mobile, uuic web, uuic admin etc
	Versions []string `bson:"versions"` //1.1.0, 1.2.0 etc

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}
