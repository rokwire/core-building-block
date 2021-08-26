package storage

import (
	"core-building-block/core/model"
	"time"
)

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
