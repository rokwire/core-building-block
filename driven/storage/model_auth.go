package storage

import "time"

type loginSession struct {
	ID string `bson:"_id"`

	AppID string `bson:"app_id"`
	OrgID string `bson:"org_id"`

	AuthTypeID   string `bson:"auth_type_id"`
	AuthTypeCode string `bson:"auth_type_code"`

	Anonymous bool `bson:"anonymous"`

	Identifier string `bson:"identifier"`

	AccountAuthTypeID         *string `bson:"account_auth_type_id"`
	AccountAuthTypeIdentifier *string `bson:"account_auth_type_identifier"`

	DeviceID string `bson:"device_id"`

	IP           string                 `bson:"ip"`
	AccessToken  string                 `bson:"access_token"`
	RefreshToken string                 `bson:"refresh_token"`
	Params       map[string]interface{} `bson:"params"`

	Expires time.Time `bson:"expires"`

	DateUpdated *time.Time `bson:"date_updated"`
	DateCreated time.Time  `bson:"date_created"`
}
