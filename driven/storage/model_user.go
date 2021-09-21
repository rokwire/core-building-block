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

	PhotoURL  string `bson:"photo_url"`
	FirstName string `bson:"first_name"`
	LastName  string `bson:"last_name"`
	Email     string `bson:"email"`
	Phone     string `bson:"phone"`
	BirthYear int8   `bson:"birth_year"`
	Address   string `bson:"address"`
	ZipCode   string `bson:"zip_code"`
	State     string `bson:"state"`
	Country   string `bson:"country"`

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

	Accounts []string `bson:"accounts"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}
