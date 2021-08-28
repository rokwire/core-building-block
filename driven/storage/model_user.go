package storage

import (
	"core-building-block/core/model"
	"time"
)

type user struct {
	ID string `bson:"_id"`

	ApplicationsAccounts []model.ApplicationUserAccount `bson:"applications_accounts"`
	Profile              model.UserProfile              `bson:"profile"`

	Permissions              []model.GlobalPermission `bson:"permissions"`
	Roles                    []model.GlobalRole       `bson:"roles"`
	Groups                   []model.GlobalGroup      `bson:"groups"`
	OrganizationsMemberships []userMembership         `bson:"organizations_memberships"`

	Devices []userDevice `bson:"devices"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type userMembership struct {
	ID string `bson:"_id"`

	OrgID string `bson:"org_id"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type userDevice struct {
	ID   string `bson:"_id"`
	Type string `bson:"type"`

	OS         string `bson:"os"`
	MacAddress string `bson:"mac_address"`

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
