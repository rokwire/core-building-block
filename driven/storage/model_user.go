package storage

import (
	"time"
)

type account struct {
	ID string `bson:"_id"`

	AppID string `bson:"app_id,omitempty"`
	OrgID string `bson:"org_id,omitempty"`

	Permissions []applicationPermission `bson:"permissions,omitempty"`
	Roles       []applicationRole       `bson:"roles,omitempty"`
	Groups      []applicationGroup      `bson:"groups,omitempty"`

	AuthTypes []accountAuthType `bson:"auth_types,omitempty"`

	Profile   profile      `bson:"profile"`
	Anonymous bool         `bson:"anonymous"`
	Devices   []userDevice `bson:"devices,omitempty"`

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

	PhotoURL         string           `bson:"photo_url"`
	FirstName        string           `bson:"first_name"`
	LastName         string           `bson:"last_name"`
	AnonymousProfile anonymousProfile `bson:"anonymous_profile"`
	DateCreated      time.Time        `bson:"date_created"`
	DateUpdated      *time.Time       `bson:"date_updated"`
}

type anonymousProfile struct {
	ID                   string    `bson:"id"`
	Interests            []string  `bson:"interests"`
	Favorites            []string  `bson:"favorites"`
	Over13               bool      `bson:"over_13"`
	PositiveInterestTags []string  `bson:"positive_interest_tags"`
	NegativeInterestTags []string  `bson:"negative_interest_tags"`
	CreationDate         time.Time `bson:"creation_date"`
	LastModifiedDate     time.Time `bson:"last_modified_date"`
	PrivacySettings      string    `bson:"privacy_settings"`
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
