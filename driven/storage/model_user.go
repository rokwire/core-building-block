package storage

import (
	"core-building-block/core/model"
	"time"
)

type user struct {
	ID string `bson:"_id"`

	Account model.UserAccount `bson:"account"`
	Profile model.UserProfile `bson:"profile"`

	Permissions              []model.GlobalPermission `bson:"permissions"`
	Roles                    []model.GlobalRole       `bson:"roles"`
	Groups                   []model.GlobalGroup      `bson:"groups"`
	OrganizationsMemberships []userMembership         `bson:"organizations_memberships"`

	Devices []model.Device `bson:"devices"`

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

type group struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`

	OrgID string `bson:"organization_id"`

	Permissions []string `bson:"permissions"`
	Roles       []string `bson:"roles"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type role struct {
	ID          string `bson:"_id"`
	Name        string `bson:"name"`
	Description string `bson:"desciption"`

	OrgID string `bson:"organization_id"`

	Permissions []string `bson:"permissions"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type permission struct {
	ID   string `bson:"_id"`
	Name string `bson:"name"`

	OrgID string `bson:"organization_id"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}
