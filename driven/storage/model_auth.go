package storage

import "time"

type loginSession struct {
	ID string `bson:"_id"`

	Anonymous bool `bson:"anonymous"`

	Identifier        string  `bson:"identifier"`
	AccountAuthTypeID *string `bson:"account_auth_type_id"`

	DeviceID string `bson:"device_id"`

	IP           string                 `bson:"ip"`
	AccessToken  string                 `bson:"access_token"`
	RefreshToken string                 `bson:"refresh_token"`
	Params       map[string]interface{} `bson:"params"`

	Expires time.Time `bson:"expires"`

	DateUpdated *time.Time `bson:"date_updated"`
	DateCreated time.Time  `bson:"date_created"`
}
