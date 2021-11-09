package storage

import (
	"time"

	"core-building-block/core/model"
)

type account struct {
	ID string `bson:"_id"`

	AppOrgID string `bson:"app_org_id,omitempty"`

	Permissions []model.Permission `bson:"permissions,omitempty"`
	Roles       []accountRole      `bson:"roles,omitempty"`
	Groups      []accountGroup     `bson:"groups,omitempty"`

	AuthTypes []accountAuthType `bson:"auth_types,omitempty"`

	MFATypes      []mfaType `bson:"mfa_types,omitempty"`
	RecoveryCodes []string  `bson:"recovery_codes,omitempty"`

	Preferences map[string]interface{} `bson:"preferences"`
	Profile     profile                `bson:"profile"`

	Devices []userDevice `bson:"devices,omitempty"`

	// Anonymous bool         `bson:"anonymous"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type accountRole struct {
	Role     appOrgRole `bson:"role"`
	Active   bool       `bson:"active"`
	AdminSet bool       `bson:"admin_set"`
}

type accountGroup struct {
	Group    appOrgGroup `bson:"group"`
	Active   bool        `bson:"active"`
	AdminSet bool        `bson:"admin_set"`
}

type accountAuthType struct {
	ID           string                 `bson:"id"`
	AuthTypeID   string                 `bson:"auth_type_id"`
	AuthTypeCode string                 `bson:"auth_type_code"`
	Identifier   string                 `bson:"identifier"`
	Params       map[string]interface{} `bson:"params"`
	CredentialID *string                `bson:"credential_id"`
	Active       bool                   `bson:"active"`

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
	BirthYear int16  `bson:"birth_year"`
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

	OS string `bson:"os"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type device struct {
	ID   string `bson:"_id"`
	Type string `bson:"type"`

	OS string `bson:"os"`

	Accounts []string `bson:"accounts"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type credential struct {
	ID string `bson:"_id"`

	AuthTypeID        string                 `bson:"auth_type_id"`
	AccountsAuthTypes []string               `bson:"account_auth_types"`
	Verified          bool                   `bson:"verified"`
	Value             map[string]interface{} `bson:"value"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}

type mfaType struct {
	ID   string `bson:"id"`
	Type string `bson:"type"`

	Verified bool                   `bson:"verified"`
	Params   map[string]interface{} `bson:"params"` //mfa type params

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}
