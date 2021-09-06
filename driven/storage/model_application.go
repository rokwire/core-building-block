package storage

import (
	"core-building-block/core/model"
	"time"
)

type applicationGroup struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`

	AppID string `bson:"app_id"`

	Permissions []applicationPermission `bson:"permissions"`
	Roles       []applicationRole       `bson:"roles"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type applicationRole struct {
	ID          string `bson:"_id"`
	Name        string `bson:"name"`
	Description string `bson:"description"`

	AppID string `bson:"app_id"`

	Permissions []applicationPermission `bson:"permissions"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type applicationPermission struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`

	AppID string `bson:"app_id"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type organization struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`
	Type string `bson:"type"`

	Config model.OrganizationConfig `bson:"config"`

	Applications []string `bson:"applications"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}
type organizationMembership struct {
	ID     string `bson:"_id"`
	UserID string `bson:"user_id"`

	OrgID       string                 `bson:"org_id"`
	OrgUserData map[string]interface{} `bson:"org_user_data"`

	//TODO take this out
	Permissions []string `bson:"permissions"`
	Roles       []string `bson:"roles"`
	Groups      []string `bson:"groups"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}
