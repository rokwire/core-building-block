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

type device struct {
	ID   string `bson:"_id"`
	Type string `bson:"type"`

	OS         string `bson:"os"`
	MacAddress string `bson:"mac_address"`

	Users []string `bson:"users"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}
