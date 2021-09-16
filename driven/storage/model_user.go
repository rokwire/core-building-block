package storage

import (
	"time"
)

type account struct {
	ID string `bson:"_id"`

	AppID string `bson:"app_id"`
	OrgID string `bson:"org_id"`

	Permissions []applicationPermission `bson:"permissions"`
	Roles       []applicationRole       `bson:"roles"`
	Groups      []applicationGroup      `bson:"groups"`

	AuthTypes []accountAuthType `bson:"auth_types"`

	Profile profile `bson:"profile"`

	Devices []userDevice `bson:"devices"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type accountAuthType struct {
	ID           string                 `bson:"id"`
	AuthTypeID   string                 `bson:"auth_type_id"`
	Identifier   string                 `bson:"identifier"`
	Params       map[string]interface{} `bson:"params"`
	CredentialID *string                `bson:"credential_id"`
	Active       bool                   `bson:"active"`
	Active2FA    bool                   `bson:"active_2fa"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type profile struct {
	ID string `bson:"id"`

	PII pii `bson:"pii"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type pii struct {
	PhotoURL    string `bson:"photo_url"`
	FirstName   string `bson:"first_name"`
	LastName    string `bson:"last_name"`
	Address     string `bson:"address"`
	Country     string `bson:"country"`
	DateOfBirth string `bson:"date_of_birth"`
	HomeCounty  string `bson:"home_county"`
	MiddleName  string `bson:"middle_name"`
	State       string `bson:"state"`
	WorkCounty  string `bson:"work_county"`
	ZipCode     string `bson:"zip_code"`
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

	Accounts []string `bson:"accounts"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}
