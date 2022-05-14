package storage

import (
	"core-building-block/core/model"
	"time"
)

type loginSession struct {
	ID string `bson:"_id"`

	AppID string `bson:"app_id"`
	OrgID string `bson:"org_id"`

	AuthTypeCode string `bson:"auth_type_code"`

	AppTypeID         string `bson:"app_type_id"`
	AppTypeIdentifier string `bson:"app_type_identifier"`

	Anonymous bool `bson:"anonymous"`

	Identifier  string            `bson:"identifier"`
	ExternalIDs map[string]string `bson:"external_ids"`

	AccountAuthTypeID         *string `bson:"account_auth_type_id"`
	AccountAuthTypeIdentifier *string `bson:"account_auth_type_identifier"`

	DeviceID *string `bson:"device_id"`

	IPAddress     string                 `bson:"ip_address"`
	AccessToken   string                 `bson:"access_token"`
	RefreshTokens []string               `bson:"refresh_tokens"`
	Params        map[string]interface{} `bson:"params"`

	State        *string    `bson:"state,omitempty"`
	StateExpires *time.Time `bson:"state_expires,omitempty"`
	MfaAttempts  *int       `bson:"mfa_attempts,omitempty"`

	DateRefreshed *time.Time `bson:"date_refreshed"`

	DateUpdated *time.Time `bson:"date_updated"`
	DateCreated time.Time  `bson:"date_created"`
}

type serviceAccount struct {
	AccountID string `bson:"account_id"`
	Name      string `bson:"name"`

	AppID string `bson:"app_id"`
	OrgID string `bson:"org_id"`

	Permissions []model.Permission `bson:"permissions"`
	FirstParty  bool               `bson:"first_party"`

	Credentials []model.ServiceAccountCredential `bson:"credentials"`

	DateCreated time.Time  `bson:"date_created"`
	DateUpdated *time.Time `bson:"date_updated"`
}
