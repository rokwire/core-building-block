package storage

import "time"

type loginSession struct {
	ID string `bson:"_id"`

	AppID string `bson:"app_id"`
	OrgID string `bson:"org_id"`

	AuthTypeCode string `bson:"auth_type_code"`

	AppTypeID         string `bson:"app_type_id"`
	AppTypeIdentifier string `bson:"app_type_identifier"`

	Anonymous bool `bson:"anonymous"`

	Identifier string `bson:"identifier"`

	AccountAuthTypeID         *string `bson:"account_auth_type_id"`
	AccountAuthTypeIdentifier *string `bson:"account_auth_type_identifier"`

	DeviceID string `bson:"device_id"`

	IPAddress     string                 `bson:"ip_address"`
	AccessToken   string                 `bson:"access_token"`
	RefreshTokens []string               `bson:"refresh_tokens"`
	Params        map[string]interface{} `bson:"params"`

	Expires      time.Time  `bson:"expires"`
	ForceExpires *time.Time `bson:"force_expires,omitempty"`

	DateUpdated *time.Time `bson:"date_updated"`
	DateCreated time.Time  `bson:"date_created"`
}
